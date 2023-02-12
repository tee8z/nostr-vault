use actix_web::{HttpResponse, Responder};

#[utoipa::path(
    get,
    path = "/health_check",
    responses(
        (status = OK, description = "server is up"),
        (status = INTERNAL_SERVER_ERROR, description = "something went terribly wrong"),
    ),
)]
pub async fn health_check() -> impl Responder {
    HttpResponse::Ok().finish()
}
