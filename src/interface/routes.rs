use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor, GovernorLayer,
};

use crate::interface::{
    cors::build_cors,
    handlers::{callback::oauth_callback, health::health, token::exchange_token},
    state::AppState,
};

pub fn build_router(state: AppState, allowed_origins: &str) -> Router {
    // Per-IP rate limit: 5 requests / minute, burst of 5.
    // `SmartIpKeyExtractor` reads `X-Forwarded-For` / `Forwarded` headers so we
    // get the real client IP when running behind AWS Lambda Function URLs (or
    // any reverse proxy). The default `PeerIpKeyExtractor` looks at the socket
    // peer, which is the proxy itself — every request would share the same
    // bucket. Worse, on Lambda there is no peer socket at all, so the default
    // extractor errors out with `Unable To Extract Key!` and 500s every call.
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_second(12)
            .burst_size(5)
            .finish()
            .expect("valid governor config"),
    );

    // Sentry middleware ordering matters: `NewSentryLayer` must wrap every
    // request in its own hub *before* `SentryHttpLayer` reads the incoming
    // `sentry-trace` header to continue the distributed trace from the iOS
    // client. Without `with_transaction`, no transaction is created and the
    // trace ends at the proxy boundary.
    Router::new()
        .route("/oauth/token", post(exchange_token))
        .route("/oauth/callback", get(oauth_callback))
        .route("/health", get(health))
        .layer(GovernorLayer::new(governor_conf))
        .layer(sentry_tower::SentryHttpLayer::new().enable_transaction())
        .layer(sentry_tower::NewSentryLayer::new_from_top())
        .layer(build_cors(allowed_origins))
        .with_state(state)
}
