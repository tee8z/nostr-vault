use crate::configuration::{DatabaseSettings, Settings};
use crate::routes::{fetch_key, health_check, upload_key};
use actix_cors::Cors;
use actix_web::dev::Server;
use actix_web::web::Data;
use actix_web::{web, App, HttpServer};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tracing::info;
use std::net::TcpListener;
use tracing::info;
use tracing_actix_web::TracingLogger;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::routes::fetch_key,
        crate::routes::health_check,
        crate::routes::upload_key
    ),
    components(
        schemas(crate::routes::KeyLookup,
                crate::authentication::StoredKey,
                crate::routes::NewKey,
                crate::routes::UploadError,
                crate::routes::ErrorResponse)
    ),
    tags(
        (name = "nostr-vault", description = "Simple api for storing nostr private keys")
    ),
)]
struct ApiDoc;

pub struct Application {
    port: u16,
    server: Server,
}

pub struct ApplicationBaseUrl(pub String);

impl Application {
    pub async fn build(configuration: Settings) -> Result<Self, anyhow::Error> {
        let connection_pool = get_connection_pool(&configuration.database);
        let address = format!(
            "{}:{}",
            configuration.application.host, configuration.application.port
        );
        let listener = TcpListener::bind(address.clone())?;
        let port = listener.local_addr().unwrap().port();
        let server = run(
            address,
            listener,
            connection_pool,
            configuration.application.base_url,
        )
        .await?;
        Ok(Self { port, server })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub async fn run_until_stopped(self) -> Result<(), std::io::Error> {
        self.server.await
    }
}

pub fn get_connection_pool(configuration: &DatabaseSettings) -> PgPool {
    PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_secs(2))
        .connect_lazy_with(configuration.with_db())
}

//We are creating an App instance on every thread
pub async fn run(
    address: String,
    listener: TcpListener,
    db_pool: PgPool,
    base_url: String,
) -> Result<Server, anyhow::Error> {
    let db_pool = Data::new(db_pool);
    let base_url = Data::new(ApplicationBaseUrl(base_url));
    let server = HttpServer::new(move || {
        let cors = Cors::default().allow_any_origin().send_wildcard();
        let openapi = ApiDoc::openapi();
        App::new()
            .wrap(TracingLogger::default())
            .wrap(cors)
            .route("/fetch_key", web::post().to(fetch_key))
            .route("/upload_key", web::post().to(upload_key))
            .route("/health_check", web::get().to(health_check))
            .app_data(db_pool.clone())
            .app_data(base_url.clone())
            .service(SwaggerUi::new("/swagger-ui/{_:.*}").url("/api-doc/openapi.json", openapi))
    })
    .listen(listener)?
    .run();
    info!("running at http://{}/swagger-ui/  ", address);
    Ok(server)
}
