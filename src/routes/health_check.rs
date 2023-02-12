use actix_web::{HttpResponse, Responder};

#[utoipa::path(
    get,
    path = "/health_check",
    responses(
        (status = OK, description = "Server is up."),
        (status = INTERNAL_SERVER_ERROR, description = "Something went terribly wrong."),
    ),
)]
pub async fn health_check() -> impl Responder {
    HttpResponse::Ok().finish()
}
