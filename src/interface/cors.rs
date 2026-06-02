use axum::http::{HeaderValue, Method};
use tower_http::cors::{AllowOrigin, CorsLayer};

pub fn build_cors(allowed_origins: &str) -> CorsLayer {
    let origins: Vec<HeaderValue> = allowed_origins
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| HeaderValue::from_str(s).ok())
        .collect();

    let layer = CorsLayer::new()
        .allow_methods([Method::POST, Method::GET, Method::OPTIONS])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderName::from_static("x-pinkha-timestamp"),
            axum::http::HeaderName::from_static("x-pinkha-nonce"),
            axum::http::HeaderName::from_static("x-pinkha-signature"),
        ]);

    if origins.is_empty() {
        // No browser origin allowed. The iOS app uses URLSession, which never
        // triggers CORS — so this is the safe default for a native-only client.
        layer
    } else {
        layer.allow_origin(AllowOrigin::list(origins))
    }
}
