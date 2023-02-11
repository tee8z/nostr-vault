use crate::authentication::{get_stored_key, AuthError};
use crate::domain::{Lookup, Nip05ID, Pin};
use crate::routes::error_chain_fmt;
use actix_web::{web, ResponseError};
use reqwest::StatusCode;
use secrecy::Secret;
use sqlx::PgPool;
use std::fmt::Debug;

#[derive(serde::Deserialize)]
pub struct KeyLookup {
    pub nip_05_id: String,
    pub pin: Secret<u64>,
}

#[derive(thiserror::Error)]
pub enum LookupError {
    #[error("{0}")]
    ValidationError(String),
    #[error("There is no private key associated with the provided pin and user.")]
    NotFoundError,
    #[error("Pin is not valid for provided user.")]
    InvalidPin,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

impl Debug for LookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        error_chain_fmt(self, f)
    }
}

impl ResponseError for LookupError {
    fn status_code(&self) -> reqwest::StatusCode {
        match self {
            LookupError::NotFoundError => StatusCode::NOT_FOUND,
            LookupError::InvalidPin => StatusCode::FORBIDDEN,
            LookupError::ValidationError(_) => StatusCode::BAD_REQUEST,
            LookupError::UnexpectedError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[tracing::instrument(
    skip(key_lookup, pool),
    fields(
        nip_05_id = %key_lookup.nip_05_id,
    )
)]
pub async fn fetch_key(
    key_lookup: web::Json<KeyLookup>,
    pool: web::Data<PgPool>,
) -> Result<String, LookupError> {
    let nip_05_id = Nip05ID::parse(key_lookup.0.nip_05_id).map_err(LookupError::ValidationError)?;
    let pin = Pin::parse(key_lookup.0.pin).map_err(LookupError::ValidationError)?;

    let lookup = &Lookup { nip_05_id, pin };

    let key = get_stored_key(lookup, &pool).await.map_err(|e| match e {
        AuthError::InvalidPin(_) => LookupError::InvalidPin,
        AuthError::UnexpectedError(e) => LookupError::UnexpectedError(e),
    })?;

    match key {
        Some(val) => Ok(val.to_string()),
        None => Err(LookupError::NotFoundError),
    }
}
