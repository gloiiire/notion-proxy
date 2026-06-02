use std::sync::Arc;

use notion_proxy::{
    application::exchange_token::ExchangeTokenUseCase,
    infrastructure::{config::Config, notion_http::NotionHttpGateway, system_clock::SystemClock},
    interface::{routes::build_router, state::AppState},
};

#[tokio::main]
async fn main() -> Result<(), lambda_http::Error> {
    let _ = dotenvy::dotenv();
    let cfg = Config::from_env();

    let guard = sentry::init((
        cfg.sentry_dsn.clone(),
        sentry::ClientOptions {
            release: sentry::release_name!(),
            traces_sample_rate: 0.1,
            ..Default::default()
        },
    ));
    Box::leak(Box::new(guard));

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "notion_proxy=info".into()),
        )
        .init();

    let notion = NotionHttpGateway::new(
        reqwest::Client::new(),
        cfg.notion_base_url,
        cfg.notion_client_id,
        cfg.notion_client_secret,
    );
    let clock = SystemClock;
    let use_case = ExchangeTokenUseCase::new(notion, clock, cfg.hmac_secret);

    let state = AppState {
        exchange_token: Arc::new(use_case),
    };

    let app = build_router(state, &cfg.allowed_origins);

    // Runtime split: AWS Lambda injects `AWS_LAMBDA_FUNCTION_NAME` into the
    // environment of every invocation. When present, hand the axum service to
    // `lambda_http::run`; otherwise fall back to the local TCP listener for
    // `cargo run` and integration tests.
    if Config::is_lambda() {
        tracing::info!("starting on Lambda runtime");
        lambda_http::run(app).await
    } else {
        let addr = format!("0.0.0.0:{}", cfg.port);
        tracing::info!("listening on {addr}");
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;
        Ok(())
    }
}
