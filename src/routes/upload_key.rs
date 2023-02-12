use crate::authentication::{save_private_key_and_pin, StoredKey};
use crate::domain::{KeyInfo, Nip05ID, Pin, PrivateKeyHash};
use crate::routes::error_chain_fmt;
use actix_web::{web, ResponseError, HttpResponse};
use reqwest::StatusCode;
use secrecy::Secret;
use sqlx::PgPool;
use std::fmt::Debug;
use utoipa::ToSchema;

use super::ErrorResponse;

#[derive(ToSchema, serde::Deserialize)]
pub struct NewKey {
    pub nip_05_id: String,
    pub pin: Secret<u64>,
    pub pk: Secret<String>,
}

#[derive(ToSchema, thiserror::Error)]
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
    path = "/upload_key",
    responses(
        (status = OK, 
            body = StoredKey, 
            example=json!(StoredKey{
                id: 1000,
                created_at: "2023-02-12T01:49:35+00:00".to_string(),
                nip_05_id: "the_name_is_bob_bob_smith@frogs.cloud".to_string(),
                private_key_hash: "f913b8539438070c0920853da25e8d1a94d799d2b717ac6358ad77b141792989".to_string(),
            }), 
            description = "successfully stored key"),
        (
            status = BAD_REQUEST, 
            body = ErrorResponse,example=json!(ErrorResponse{
                ok: false,
                error: "f913b8539438070c0920853da25e8d1a94d799d2b717ac6358ad77b141792989 is not a valid private key.".to_string()
            }),
            description = "object used to upload the private key fails validation"
        ),
        (
            status = INTERNAL_SERVER_ERROR, 
            body = ErrorResponse, 
            example=json!(ErrorResponse{
                ok: false,
                error: "failed to save private key".to_string()
            }),
            description = "something went terribly wrong"
        ),
    ),
    request_body = NewKey
)]
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
