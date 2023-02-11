use crate::domain::{KeyInfo, Pin};
use crate::telemetry::spawn_blocking_with_tracing;
use anyhow::Context;
use argon2::password_hash::SaltString;
use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version};
use secrecy::{ExposeSecret, Secret};
use sqlx::PgPool;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct StoredKey {
    pub id: i64,
    pub created_at: String,
    pub nip_05_id: String,
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
        key_info.private_key.as_ref()
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

/*
#[tracing::instrument(name = "Get stored pin", skip(username, pool))]
async fn get_stored_pin(
    username: &str,
    pool: &PgPool,
) -> Result<Option<(uuid::Uuid, Secret<String>)>, anyhow::Error> {
    let row = sqlx::query!(
        r#"
        SELECT user_id, password_hash
        FROM users
        WHERE username = $1
        "#,
        username,
    )
    .fetch_optional(pool)
    .await
    .context("Failed to performed a query to retrieve stored credentials.")?
    .map(|row| (row.user_id, Secret::new(row.password_hash)));
    Ok(row)
}
*/
