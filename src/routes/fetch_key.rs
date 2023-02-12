use crate::authentication::{get_stored_key, AuthError, StoredKey};
use crate::domain::{Lookup, Nip05ID, Pin};
use crate::routes::error_chain_fmt;
use actix_web::{web, ResponseError, HttpResponse};
use reqwest::StatusCode;
use secrecy::Secret;
use sqlx::PgPool;
use std::fmt::Debug;
use utoipa::ToSchema;

use super::ErrorResponse;

#[derive(ToSchema, serde::Deserialize)]
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
    fn error_response(&self) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        HttpResponse::build(self.status_code())
        .json(ErrorResponse { 
            ok: false,
            error: self.to_string()
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
                    private_key_hash: "f913b8539438070c0920853da25e8d1a94d799d2b717ac6358ad77b141792989".to_string(),
                }),  
                description = "successfully found pin"
            ),
            (
                status = FORBIDDEN, 
                body = ErrorResponse,  
                example=json!(ErrorResponse{
                    ok: false,
                    error: "Pin is not valid for provided user.".to_string()
                }),
                description = "nip 05 id found, but pin does not match"
            ),
            (
                status = BAD_REQUEST, 
                body = ErrorResponse,
                example=json!(ErrorResponse{
                    ok: false,
                    error: "8ehd99 is not a valid pin.".to_string()
                }),
                description = "object used to request the private key fails validation"
            ),
            (
                status = NOT_FOUND, 
                body = ErrorResponse,
                example=json!(ErrorResponse{
                    ok: false,
                    error: "There is no private key associated with the provided pin and user".to_string()
                }),
                description = "nip 05 it and pin pairing not found"
            ),
            (
                status = INTERNAL_SERVER_ERROR, 
                body =  ErrorResponse, 
                example=json!(ErrorResponse{
                    ok: false,
                    error: "unable to connect to db".to_string()
                }),
                description = "something went terribly wrong"
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
