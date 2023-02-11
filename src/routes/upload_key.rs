use crate::authentication::save_private_key_and_pin;
use crate::domain::{KeyInfo, Nip05ID, Pin, PrivateKeyHash};
use crate::routes::error_chain_fmt;
use actix_web::{web, ResponseError};
use reqwest::StatusCode;
use secrecy::Secret;
use sqlx::PgPool;
use std::fmt::Debug;

#[derive(serde::Deserialize)]
pub struct NewKey {
    pub nip_05_id: String,
    pub pin: Secret<u64>,
    pub pk: Secret<String>,
}

#[derive(thiserror::Error)]
pub enum UploadError {
    #[error("{0}")]
    ValidationError(String),
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

impl Debug for UploadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        error_chain_fmt(self, f)
    }
}

impl ResponseError for UploadError {
    fn status_code(&self) -> reqwest::StatusCode {
        match self {
            UploadError::ValidationError(_) => StatusCode::BAD_REQUEST,
            UploadError::UnexpectedError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[tracing::instrument(
    skip(new_key, pool),
    fields(
        nip_05_id = %new_key.nip_05_id,
    )
)]
pub async fn upload_key(
    new_key: web::Json<NewKey>,
    pool: web::Data<PgPool>,
) -> Result<String, UploadError> {
    let nip_05_id = Nip05ID::parse(new_key.0.nip_05_id).map_err(UploadError::ValidationError)?;
    let private_key_hash =
        PrivateKeyHash::parse(new_key.0.pk).map_err(UploadError::ValidationError)?;
    let pin = Pin::parse(new_key.0.pin).map_err(UploadError::ValidationError)?;

    let key_info = &KeyInfo {
        nip_05_id,
        pin,
        private_key_hash,
    };

    let stored_key = save_private_key_and_pin(key_info, &pool)
        .await
        .expect("failed to save private key and pin");

    Ok(stored_key.to_string())
}
