use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::Response,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tower::ServiceExt;

use notion_proxy::{
    application::exchange_token::ExchangeTokenUseCase,
    domain::{
        ports::{Clock, NotionError, NotionGateway},
        token::NotionToken,
    },
    interface::{routes::build_router, state::AppState},
};

type HmacSha256 = Hmac<Sha256>;

struct FakeGateway {
    result: Mutex<Option<Result<NotionToken, NotionError>>>,
}

impl FakeGateway {
    fn ok(t: NotionToken) -> Self {
        Self {
            result: Mutex::new(Some(Ok(t))),
        }
    }

    fn err(e: NotionError) -> Self {
        Self {
            result: Mutex::new(Some(Err(e))),
        }
    }
}

#[async_trait]
impl NotionGateway for FakeGateway {
    async fn exchange_code(&self, _: &str, _: &str) -> Result<NotionToken, NotionError> {
        self.result
            .lock()
            .unwrap()
            .take()
            .expect("FakeGateway used twice")
    }
}

struct FixedClock(i64);

impl Clock for FixedClock {
    fn now_unix(&self) -> i64 {
        self.0
    }
}

fn token() -> NotionToken {
    NotionToken {
        access_token: "tok".into(),
        token_type: "bearer".into(),
        bot_id: "bot".into(),
        workspace_id: "ws-1".into(),
        workspace_name: None,
        workspace_icon: None,
        owner: serde_json::json!({}),
        duplicated_template_id: None,
        request_id: None,
    }
}

fn build_app(
    gateway: impl NotionGateway + 'static,
    secret: Vec<u8>,
    now: i64,
) -> axum::Router {
    build_app_with_origins(gateway, secret, now, "")
}

fn build_app_with_origins(
    gateway: impl NotionGateway + 'static,
    secret: Vec<u8>,
    now: i64,
    origins: &str,
) -> axum::Router {
    let uc = ExchangeTokenUseCase::new(gateway, FixedClock(now), secret);
    let state = AppState {
        exchange_token: Arc::new(uc),
    };
    build_router(state, origins)
}

fn sign(secret: &[u8], ts: &str, nonce: &str, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(ts.as_bytes());
    mac.update(b"\n");
    mac.update(nonce.as_bytes());
    mac.update(b"\n");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

fn signed_token_request(secret: &[u8], ts: i64, nonce: &str, body: &[u8]) -> Request<Body> {
    let ts_str = ts.to_string();
    let sig = sign(secret, &ts_str, nonce, body);
    Request::builder()
        .method("POST")
        .uri("/oauth/token")
        // SmartIpKeyExtractor needs a forwarded IP; otherwise the rate limiter
        // can't compute a key and returns 500 before the handler runs.
        .header("x-forwarded-for", "127.0.0.1")
        .header("content-type", "application/json")
        .header("x-pinkha-timestamp", ts_str)
        .header("x-pinkha-nonce", nonce)
        .header("x-pinkha-signature", sig)
        .body(Body::from(body.to_vec()))
        .unwrap()
}

async fn read_body(response: Response) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec()
}

#[tokio::test]
async fn health_returns_ok() {
    let app = build_app(FakeGateway::ok(token()), b"secret".to_vec(), 100);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .header("x-forwarded-for", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(read_body(resp).await, b"ok");
}

#[tokio::test]
async fn callback_redirects_to_pinkha_scheme() {
    let app = build_app(FakeGateway::ok(token()), b"secret".to_vec(), 100);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/oauth/callback?code=xyz&state=abc")
                .header("x-forwarded-for", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.starts_with("pinkha://oauth/notion?"));
    assert!(location.contains("code=xyz"));
    assert!(location.contains("state=abc"));
}

#[tokio::test]
async fn callback_forwards_error_from_notion() {
    let app = build_app(FakeGateway::ok(token()), b"secret".to_vec(), 100);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/oauth/callback?error=access_denied")
                .header("x-forwarded-for", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.contains("error=access_denied"));
}

#[tokio::test]
async fn exchange_token_happy_path() {
    let secret = b"secret".to_vec();
    let body = br#"{"code":"abc","redirect_uri":"https://app"}"#;
    let app = build_app(FakeGateway::ok(token()), secret.clone(), 100);

    let req = signed_token_request(&secret, 100, "nonce-1", body);
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&read_body(resp).await).unwrap();
    assert_eq!(json["access_token"], "tok");
    assert_eq!(json["workspace_id"], "ws-1");
}

#[tokio::test]
async fn exchange_token_missing_signature_header() {
    let app = build_app(FakeGateway::ok(token()), b"secret".to_vec(), 100);
    let req = Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header("x-forwarded-for", "127.0.0.1")
        .header("content-type", "application/json")
        .header("x-pinkha-timestamp", "100")
        .header("x-pinkha-nonce", "n")
        .body(Body::from(b"{}".to_vec()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let json: serde_json::Value = serde_json::from_slice(&read_body(resp).await).unwrap();
    assert_eq!(json["error"], "missing X-Pinkha-Signature");
}

#[tokio::test]
async fn exchange_token_bad_hex_signature() {
    let app = build_app(FakeGateway::ok(token()), b"secret".to_vec(), 100);
    let req = Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header("x-forwarded-for", "127.0.0.1")
        .header("content-type", "application/json")
        .header("x-pinkha-timestamp", "100")
        .header("x-pinkha-nonce", "n")
        .header("x-pinkha-signature", "not-hex!!")
        .body(Body::from(b"{}".to_vec()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn exchange_token_invalid_signature() {
    let secret = b"secret".to_vec();
    let body = br#"{"code":"abc","redirect_uri":"https://app"}"#;
    let app = build_app(FakeGateway::ok(token()), secret, 100);

    // Valid hex but wrong content
    let req = Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header("x-forwarded-for", "127.0.0.1")
        .header("content-type", "application/json")
        .header("x-pinkha-timestamp", "100")
        .header("x-pinkha-nonce", "n")
        .header("x-pinkha-signature", "deadbeef".repeat(8))
        .body(Body::from(body.to_vec()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn exchange_token_upstream_error_returns_502() {
    let secret = b"secret".to_vec();
    let body = br#"{"code":"abc","redirect_uri":"https://app"}"#;
    let gateway = FakeGateway::err(NotionError::Upstream {
        status: 401,
        body: "denied".into(),
    });
    let app = build_app(gateway, secret.clone(), 100);

    let req = signed_token_request(&secret, 100, "nonce-1", body);
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    let json: serde_json::Value = serde_json::from_slice(&read_body(resp).await).unwrap();
    assert_eq!(json["error"], "denied");
}

#[tokio::test]
async fn exchange_token_upstream_unreachable() {
    let secret = b"secret".to_vec();
    let body = br#"{"code":"abc","redirect_uri":"https://app"}"#;
    let gateway = FakeGateway::err(NotionError::Network("dns".into()));
    let app = build_app(gateway, secret.clone(), 100);

    let req = signed_token_request(&secret, 100, "nonce-1", body);
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn exchange_token_missing_timestamp_header() {
    let app = build_app(FakeGateway::ok(token()), b"secret".to_vec(), 100);
    let req = Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header("x-forwarded-for", "127.0.0.1")
        .header("content-type", "application/json")
        .header("x-pinkha-nonce", "n")
        .header("x-pinkha-signature", "deadbeef")
        .body(Body::from(b"{}".to_vec()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let json: serde_json::Value = serde_json::from_slice(&read_body(resp).await).unwrap();
    assert_eq!(json["error"], "missing X-Pinkha-Timestamp");
}

#[tokio::test]
async fn exchange_token_missing_nonce_header() {
    let app = build_app(FakeGateway::ok(token()), b"secret".to_vec(), 100);
    let req = Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header("x-forwarded-for", "127.0.0.1")
        .header("content-type", "application/json")
        .header("x-pinkha-timestamp", "100")
        .header("x-pinkha-signature", "deadbeef")
        .body(Body::from(b"{}".to_vec()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let json: serde_json::Value = serde_json::from_slice(&read_body(resp).await).unwrap();
    assert_eq!(json["error"], "missing X-Pinkha-Nonce");
}

#[tokio::test]
async fn cors_allows_configured_origin_on_preflight() {
    let app = build_app_with_origins(
        FakeGateway::ok(token()),
        b"secret".to_vec(),
        100,
        "https://allowed.example",
    );
    let req = Request::builder()
        .method("OPTIONS")
        .uri("/oauth/token")
        .header("x-forwarded-for", "127.0.0.1")
        .header("origin", "https://allowed.example")
        .header("access-control-request-method", "POST")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("https://allowed.example")
    );
}

#[tokio::test]
async fn cors_omits_allow_origin_for_unlisted_origin() {
    let app = build_app_with_origins(
        FakeGateway::ok(token()),
        b"secret".to_vec(),
        100,
        "https://allowed.example",
    );
    let req = Request::builder()
        .method("OPTIONS")
        .uri("/oauth/token")
        .header("x-forwarded-for", "127.0.0.1")
        .header("origin", "https://other.example")
        .header("access-control-request-method", "POST")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert!(resp.headers().get("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn cors_empty_allowlist_omits_allow_origin() {
    // Default for the native iOS client: no browser origin gets allowed.
    let app = build_app(FakeGateway::ok(token()), b"secret".to_vec(), 100);
    let req = Request::builder()
        .method("OPTIONS")
        .uri("/oauth/token")
        .header("x-forwarded-for", "127.0.0.1")
        .header("origin", "https://anything.example")
        .header("access-control-request-method", "POST")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert!(resp.headers().get("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn rate_limiter_blocks_after_burst() {
    let secret = b"secret".to_vec();
    let body = br#"{"code":"abc","redirect_uri":"https://app"}"#;
    // Each request gets a fresh OK gateway via a fresh use case... but the
    // governor state lives in the Router, so all requests share its bucket.
    // We only need ONE successful response shape; subsequent calls past the
    // burst should be rate-limited *before* hitting the use case.
    let app = build_app(
        AlwaysOkGateway,
        secret.clone(),
        100,
    );

    // Burst size is 5 → first 5 succeed, 6th is throttled.
    let mut last_status = StatusCode::IM_A_TEAPOT;
    for i in 0..6 {
        let req = signed_token_request(&secret, 100, &format!("n-{i}"), body);
        let resp = app.clone().oneshot(req).await.unwrap();
        last_status = resp.status();
        if i < 5 {
            assert_eq!(last_status, StatusCode::OK, "request {i} should succeed");
        }
    }
    assert_eq!(
        last_status,
        StatusCode::TOO_MANY_REQUESTS,
        "6th request should be rate-limited"
    );
}

// Always-OK gateway for the rate-limit test: avoids the "FakeGateway used twice"
// panic since each request would otherwise need its own result slot.
struct AlwaysOkGateway;

#[async_trait]
impl NotionGateway for AlwaysOkGateway {
    async fn exchange_code(&self, _: &str, _: &str) -> Result<NotionToken, NotionError> {
        Ok(token())
    }
}
