use crate::domain::{KeyInfo, Lookup, Pin, RowData};
use crate::telemetry::spawn_blocking_with_tracing;
use anyhow::Context;
use argon2::password_hash::SaltString;
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use secrecy::{ExposeSecret, Secret};
use sqlx::PgPool;

#[derive(thiserror::Error, Debug)]
pub enum AuthError {
    #[error("Invalid pin.")]
    InvalidPin(#[source] anyhow::Error),
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct StoredKey {
    pub id: i64,
    pub created_at: String,
    pub nip_05_id: String,
    pub private_key_hash: String,
}

impl std::fmt::Display for StoredKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let as_json = serde_json::to_string(&self).unwrap();
        write!(f, "{}", as_json)
    }
}

#[tracing::instrument(name = "Store private key and pin", skip(key_info, pool))]
pub async fn save_private_key_and_pin(
    key_info: &KeyInfo,
    pool: &PgPool,
) -> Result<StoredKey, anyhow::Error> {
    let pin = key_info.pin.clone();
    let pin_hash = spawn_blocking_with_tracing(move || compute_pin_hash(pin))
        .await?
        .context("Failed to hash pin")?;

    let record = sqlx::query!(
        r#"
    INSERT INTO keys (nip_05_id, pin_hash, private_key_hash)
    VALUES ($1, $2, $3)
    RETURNING id, created_at
        "#,
        key_info.nip_05_id.to_string(),
        pin_hash.expose_secret().to_string(),
        key_info.private_key_hash.as_ref()
    )
    .fetch_one(pool)
    .await
    .map_err(|e| {
        tracing::error!("Failed to execute query: {:?}", e);
        e
    })?;
    let stored = StoredKey {
        id: record.id,
        nip_05_id: key_info.nip_05_id.to_string(),
        created_at: record.created_at.to_rfc3339(),
        private_key_hash: key_info.private_key_hash.as_ref().to_string(),
    };
    Ok(stored)
}

fn compute_pin_hash(raw_pin: Pin) -> Result<Secret<String>, anyhow::Error> {
    let salt = SaltString::generate(&mut rand::thread_rng());
    let pin_hash = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(15000, 2, 1, None).unwrap(),
    )
    .hash_password(raw_pin.as_ref().as_bytes(), &salt)?
    .to_string();
    Ok(Secret::new(pin_hash))
}

#[tracing::instrument(name = "Get stored key", skip(lookup, pool))]
pub async fn get_stored_key(
    lookup: &Lookup,
    pool: &PgPool,
) -> Result<Option<StoredKey>, AuthError> {
    let stored_key = sqlx::query!(
        r#"
        SELECT id, created_at, nip_05_id, private_key_hash, pin_hash
        FROM keys
        WHERE nip_05_id = $1;
        "#,
        lookup.nip_05_id.to_string()
    )
    .fetch_optional(pool)
    .await
    .context("Failed to performed a query to retrieve stored key.")?
    .map(|row| RowData {
        id: row.id,
        created_at: row.created_at,
        nip_05_id: row.nip_05_id,
        private_key_hash: Secret::new(row.private_key_hash),
        pin_hash: Secret::new(row.pin_hash),
    });

    let mut expected_pin_hash = Secret::new(
        "$argon2id$v=19$m=15000,t=2,p=1$\
            gZiV/M1gPc22ElAH/Jh1Hw$\
            CWOrkoo7oJBQ/iyh7uJ0LO2aLEfrHwTWllSAxT0zRno"
            .to_string(),
    );

    if stored_key.as_ref().is_some() {
        expected_pin_hash = stored_key.clone().unwrap().pin_hash;
    }
    let pin = lookup.pin.clone();
    spawn_blocking_with_tracing(move || verify_pin(expected_pin_hash, pin))
        .await
        .context("Failed to spawn blocking task.")??;

    Ok(stored_key.map(|row| StoredKey {
        id: row.id,
        nip_05_id: row.nip_05_id,
        created_at: row.created_at.to_rfc3339(),
        private_key_hash: row.private_key_hash.expose_secret().to_string(),
    }))
}

fn verify_pin(expected_pin_hash: Secret<String>, pin_candidate: Pin) -> Result<(), AuthError> {
    let expected_pin_hash = PasswordHash::new(expected_pin_hash.expose_secret())
        .context("Failed to parse hash in PHC string format.")?;

    Argon2::default()
        .verify_password(pin_candidate.as_ref().as_bytes(), &expected_pin_hash)
        .context("Invalid pin.")
        .map_err(AuthError::InvalidPin)
}
