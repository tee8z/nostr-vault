use crate::authentication::{get_stored_key, AuthError, StoredKey};
use crate::domain::{Lookup, Nip05ID, Pin};
use crate::routes::error_chain_fmt;
use actix_web::{web, HttpResponse, ResponseError};
use reqwest::StatusCode;
use secrecy::Secret;
use sqlx::PgPool;
use std::fmt::Debug;
use utoipa::ToSchema;

use super::ErrorResponse;

#[derive(ToSchema, serde::Deserialize)]
pub struct KeyLookup {
    #[schema(example = "the_name_is_bob_bob_smith@frogs.cloud")]
    pub nip_05_id: String,
    #[schema(value_type = u64, example = "401267")]
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
    fn error_response(&self) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        HttpResponse::build(self.status_code()).json(ErrorResponse {
            value: self.to_string(),
        })
    }
}

#[utoipa::path(
        post,
        path = "/fetch_key",
        responses(
            (status = OK,
                body = StoredKey,
                example=json!(
                StoredKey{
                    id: 1000,
                    created_at: "2023-02-12T01:49:35+00:00".to_string(),
                    nip_05_id: "the_name_is_bob_bob_smith@frogs.cloud".to_string(),
                    private_key_hash: "$PBKDF2$i=100000,l=256,s=0Bu5lWu4s66/iottrlUGdckjf5nwnpB05jwp4yDh8NU=$AESGM$OrScsD+hHGaRaPbc$XMXVVbjt3JV+QsNb7ZWRc8uNod2YzJL0lSvW1FOiY38ywOu7IEChKs/IqEQ7knhZAmRGYqoB4dhAbdOTwVhYIeQsuf1+f+9ARPEjtURsDg==".to_string(),
                }),
                description = "Successfully found pin."
            ),
            (
                status = FORBIDDEN,
                body = ErrorResponse,
                example=json!(ErrorResponse{
                    value: "Pin is not valid for provided user.".to_string()
                }),
                description = "nip 05 id found, but pin does not match"
            ),
            (
                status = BAD_REQUEST,
                body = ErrorResponse,
                example=json!(ErrorResponse{
                    value: "8ehd99 is not a valid pin.".to_string()
                }),
                description = "object used to request the private key fails validation"
            ),
            (
                status = NOT_FOUND,
                body = ErrorResponse,
                example=json!(ErrorResponse{
                    value: "There is no private key associated with the provided pin and user.".to_string()
                }),
                description = "nip_05_id and pin pairing not found"
            ),
            (
                status = INTERNAL_SERVER_ERROR,
                body =  ErrorResponse,
                example=json!(ErrorResponse{
                    value: "Unable to connect to db.".to_string()
                }),
                description = "Something went terribly wrong."
            ),
        ),
        request_body = KeyLookup
)]
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
