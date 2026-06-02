//! End-to-end tests: real `NotionHttpGateway` (reqwest) → wiremock mock of
//! `api.notion.com`. Exercises the full chain — axum router, HMAC verification,
//! reqwest outbound, response parsing — without leaving the test process.

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tower::ServiceExt;
use wiremock::{
    matchers::{header, method, path},
    Mock, MockServer, ResponseTemplate,
};

use notion_proxy::{
    application::exchange_token::ExchangeTokenUseCase,
    infrastructure::{notion_http::NotionHttpGateway, system_clock::SystemClock},
    interface::{routes::build_router, state::AppState},
};

type HmacSha256 = Hmac<Sha256>;

fn sign(secret: &[u8], ts: &str, nonce: &str, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(ts.as_bytes());
    mac.update(b"\n");
    mac.update(nonce.as_bytes());
    mac.update(b"\n");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

fn build_app(base_url: String, secret: Vec<u8>) -> axum::Router {
    let gateway = NotionHttpGateway::new(
        reqwest::Client::new(),
        base_url,
        "client-id".into(),
        "client-secret".into(),
    );
    let uc = ExchangeTokenUseCase::new(gateway, SystemClock, secret);
    let state = AppState {
        exchange_token: Arc::new(uc),
    };
    build_router(state, "")
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

async fn read_body(response: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec()
}

#[tokio::test]
async fn full_chain_succeeds_with_notion_200() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/oauth/token"))
        .and(header("Notion-Version", "2022-06-28"))
        // basic auth: base64("client-id:client-secret") = "Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ="
        .and(header(
            "Authorization",
            "Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "real-tok",
            "token_type": "bearer",
            "bot_id": "real-bot",
            "workspace_id": "real-ws",
            "owner": {"type": "user"},
        })))
        .mount(&server)
        .await;

    let secret = b"e2e-secret".to_vec();
    let app = build_app(server.uri(), secret.clone());

    let body = br#"{"code":"auth-code","redirect_uri":"https://pinkha.app/cb"}"#;
    let ts = now_unix().to_string();
    let nonce = "e2e-nonce";
    let sig = sign(&secret, &ts, nonce, body);

    let req = Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header("x-forwarded-for", "127.0.0.1")
        .header("content-type", "application/json")
        .header("x-pinkha-timestamp", &ts)
        .header("x-pinkha-nonce", nonce)
        .header("x-pinkha-signature", sig)
        .body(Body::from(body.to_vec()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json: serde_json::Value = serde_json::from_slice(&read_body(resp).await).unwrap();
    assert_eq!(json["access_token"], "real-tok");
    assert_eq!(json["workspace_id"], "real-ws");
    assert_eq!(json["owner"]["type"], "user");
}

#[tokio::test]
async fn full_chain_propagates_notion_401() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/oauth/token"))
        .respond_with(ResponseTemplate::new(401).set_body_string("invalid_grant"))
        .mount(&server)
        .await;

    let secret = b"e2e-secret".to_vec();
    let app = build_app(server.uri(), secret.clone());

    let body = br#"{"code":"bad","redirect_uri":"https://pinkha.app/cb"}"#;
    let ts = now_unix().to_string();
    let nonce = "n2";
    let sig = sign(&secret, &ts, nonce, body);

    let req = Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header("x-forwarded-for", "127.0.0.1")
        .header("content-type", "application/json")
        .header("x-pinkha-timestamp", &ts)
        .header("x-pinkha-nonce", nonce)
        .header("x-pinkha-signature", sig)
        .body(Body::from(body.to_vec()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

    let json: serde_json::Value = serde_json::from_slice(&read_body(resp).await).unwrap();
    assert_eq!(json["error"], "invalid_grant");
}

#[tokio::test]
async fn full_chain_sends_correct_body_to_notion() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/oauth/token"))
        .and(wiremock::matchers::body_partial_json(serde_json::json!({
            "grant_type": "authorization_code",
            "code": "auth-code",
            "redirect_uri": "https://pinkha.app/cb",
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "t",
            "token_type": "bearer",
            "bot_id": "b",
            "workspace_id": "w",
            "owner": {},
        })))
        .expect(1)
        .mount(&server)
        .await;

    let secret = b"e2e-secret".to_vec();
    let app = build_app(server.uri(), secret.clone());

    let body = br#"{"code":"auth-code","redirect_uri":"https://pinkha.app/cb"}"#;
    let ts = now_unix().to_string();
    let nonce = "n3";
    let sig = sign(&secret, &ts, nonce, body);

    let req = Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header("x-forwarded-for", "127.0.0.1")
        .header("content-type", "application/json")
        .header("x-pinkha-timestamp", &ts)
        .header("x-pinkha-nonce", nonce)
        .header("x-pinkha-signature", sig)
        .body(Body::from(body.to_vec()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // wiremock asserts expect(1) on drop, so reaching here without panic
    // means the body matched exactly.
}

#[tokio::test]
async fn full_chain_returns_502_when_notion_unreachable() {
    // Point the gateway at a port no one is listening on. reqwest will fail
    // with a connection error, which `NotionHttpGateway` translates into
    // `NotionError::Network`, the use case into `UpstreamUnreachable`, and
    // the interface into 502.
    let secret = b"e2e-secret".to_vec();
    let app = build_app("http://127.0.0.1:1".into(), secret.clone());

    let body = br#"{"code":"abc","redirect_uri":"https://x"}"#;
    let ts = now_unix().to_string();
    let nonce = "n-unreachable";
    let sig = sign(&secret, &ts, nonce, body);

    let req = Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header("x-forwarded-for", "127.0.0.1")
        .header("content-type", "application/json")
        .header("x-pinkha-timestamp", &ts)
        .header("x-pinkha-nonce", nonce)
        .header("x-pinkha-signature", sig)
        .body(Body::from(body.to_vec()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    let json: serde_json::Value = serde_json::from_slice(&read_body(resp).await).unwrap();
    assert_eq!(json["error"], "upstream unreachable");
}

#[tokio::test]
async fn full_chain_returns_500_when_notion_sends_invalid_json() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/oauth/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string("not actually json"),
        )
        .mount(&server)
        .await;

    let secret = b"e2e-secret".to_vec();
    let app = build_app(server.uri(), secret.clone());

    let body = br#"{"code":"abc","redirect_uri":"https://x"}"#;
    let ts = now_unix().to_string();
    let nonce = "n-parse";
    let sig = sign(&secret, &ts, nonce, body);

    let req = Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header("x-forwarded-for", "127.0.0.1")
        .header("content-type", "application/json")
        .header("x-pinkha-timestamp", &ts)
        .header("x-pinkha-nonce", nonce)
        .header("x-pinkha-signature", sig)
        .body(Body::from(body.to_vec()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let json: serde_json::Value = serde_json::from_slice(&read_body(resp).await).unwrap();
    assert_eq!(json["error"], "parse error");
}

#[tokio::test]
async fn full_chain_rejects_unsigned_request_before_calling_notion() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/oauth/token"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0) // Notion should NEVER be called
        .mount(&server)
        .await;

    let secret = b"e2e-secret".to_vec();
    let app = build_app(server.uri(), secret);

    let req = Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header("x-forwarded-for", "127.0.0.1")
        .header("content-type", "application/json")
        .body(Body::from(b"{}".to_vec()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // server's expect(0) asserts on drop that Notion was not contacted.
}
