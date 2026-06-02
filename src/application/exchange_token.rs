use async_trait::async_trait;

use crate::domain::{
    ports::{Clock, NotionError, NotionGateway},
    signature::{self, SignatureError},
    token::{NotionToken, TokenExchangeRequest},
};

pub struct ExchangeTokenInput {
    pub timestamp: String,
    pub nonce: String,
    pub signature: Vec<u8>,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub enum ExchangeTokenError {
    Unauthorized(&'static str),
    BadRequest(&'static str),
    UpstreamUnreachable,
    UpstreamError { body: String },
    ParseError,
}

#[async_trait]
pub trait ExchangeTokenPort: Send + Sync {
    async fn execute(&self, input: ExchangeTokenInput) -> Result<NotionToken, ExchangeTokenError>;
}

pub struct ExchangeTokenUseCase<N: NotionGateway, C: Clock> {
    notion: N,
    clock: C,
    hmac_secret: Vec<u8>,
}

impl<N: NotionGateway, C: Clock> ExchangeTokenUseCase<N, C> {
    pub fn new(notion: N, clock: C, hmac_secret: Vec<u8>) -> Self {
        Self {
            notion,
            clock,
            hmac_secret,
        }
    }
}

#[async_trait]
impl<N: NotionGateway, C: Clock> ExchangeTokenPort for ExchangeTokenUseCase<N, C> {
    async fn execute(&self, input: ExchangeTokenInput) -> Result<NotionToken, ExchangeTokenError> {
        let now = self.clock.now_unix();
        signature::verify(
            &self.hmac_secret,
            &input.timestamp,
            &input.nonce,
            &input.signature,
            &input.body,
            now,
        )
        .map_err(|e| match e {
            SignatureError::InvalidTimestamp => {
                ExchangeTokenError::Unauthorized("invalid timestamp")
            }
            SignatureError::OutOfWindow => {
                ExchangeTokenError::Unauthorized("timestamp out of window")
            }
            SignatureError::InvalidSignature => {
                ExchangeTokenError::Unauthorized("invalid signature")
            }
        })?;

        let req: TokenExchangeRequest = serde_json::from_slice(&input.body)
            .map_err(|_| ExchangeTokenError::BadRequest("invalid JSON body"))?;

        if req.code.is_empty() {
            return Err(ExchangeTokenError::BadRequest("code is required"));
        }

        let token = self
            .notion
            .exchange_code(&req.code, &req.redirect_uri)
            .await
            .map_err(|e| match e {
                NotionError::Network(msg) => {
                    tracing::error!("Notion token exchange network error: {msg}");
                    ExchangeTokenError::UpstreamUnreachable
                }
                NotionError::Upstream { status, body } => {
                    tracing::error!("Notion returned {status}: {body}");
                    ExchangeTokenError::UpstreamError { body }
                }
                NotionError::Parse(msg) => {
                    tracing::error!("Failed to parse Notion response: {msg}");
                    ExchangeTokenError::ParseError
                }
            })?;

        tracing::info!(workspace_id = %token.workspace_id, "token exchanged successfully");
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    struct FakeNotion {
        result: Mutex<Option<Result<NotionToken, NotionError>>>,
        last_call: Mutex<Option<(String, String)>>,
    }

    impl FakeNotion {
        fn ok(token: NotionToken) -> Self {
            Self {
                result: Mutex::new(Some(Ok(token))),
                last_call: Mutex::new(None),
            }
        }

        fn err(e: NotionError) -> Self {
            Self {
                result: Mutex::new(Some(Err(e))),
                last_call: Mutex::new(None),
            }
        }
    }

    #[async_trait]
    impl NotionGateway for FakeNotion {
        async fn exchange_code(
            &self,
            code: &str,
            redirect_uri: &str,
        ) -> Result<NotionToken, NotionError> {
            *self.last_call.lock().unwrap() = Some((code.into(), redirect_uri.into()));
            self.result
                .lock()
                .unwrap()
                .take()
                .expect("FakeNotion called twice")
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
            workspace_id: "ws-123".into(),
            workspace_name: None,
            workspace_icon: None,
            owner: serde_json::json!({}),
            duplicated_template_id: None,
            request_id: None,
        }
    }

    fn make_input(secret: &[u8], body: &[u8], ts: i64) -> ExchangeTokenInput {
        let ts_str = ts.to_string();
        let nonce = "test-nonce";
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(ts_str.as_bytes());
        mac.update(b"\n");
        mac.update(nonce.as_bytes());
        mac.update(b"\n");
        mac.update(body);
        let signature = mac.finalize().into_bytes().to_vec();

        ExchangeTokenInput {
            timestamp: ts_str,
            nonce: nonce.into(),
            signature,
            body: body.to_vec(),
        }
    }

    #[tokio::test]
    async fn happy_path_returns_token_and_calls_notion() {
        let secret = b"secret".to_vec();
        let body = br#"{"code":"abc","redirect_uri":"https://app"}"#;
        let input = make_input(&secret, body, 100);

        let gateway = FakeNotion::ok(token());
        let uc = ExchangeTokenUseCase::new(gateway, FixedClock(100), secret);

        let result = uc.execute(input).await.unwrap();
        assert_eq!(result.workspace_id, "ws-123");

        let call = uc.notion.last_call.lock().unwrap().clone().unwrap();
        assert_eq!(call.0, "abc");
        assert_eq!(call.1, "https://app");
    }

    #[tokio::test]
    async fn invalid_signature_returns_unauthorized() {
        let secret = b"secret".to_vec();
        let body = b"{}";
        let mut input = make_input(&secret, body, 100);
        input.signature[0] ^= 0xff;

        let uc = ExchangeTokenUseCase::new(FakeNotion::ok(token()), FixedClock(100), secret);

        assert!(matches!(
            uc.execute(input).await,
            Err(ExchangeTokenError::Unauthorized("invalid signature"))
        ));
    }

    #[tokio::test]
    async fn malformed_timestamp_returns_unauthorized() {
        let secret = b"secret".to_vec();
        let input = ExchangeTokenInput {
            timestamp: "not-a-number".into(),
            nonce: "n".into(),
            signature: vec![0; 32],
            body: b"{}".to_vec(),
        };

        let uc = ExchangeTokenUseCase::new(FakeNotion::ok(token()), FixedClock(100), secret);

        assert!(matches!(
            uc.execute(input).await,
            Err(ExchangeTokenError::Unauthorized("invalid timestamp"))
        ));
    }

    #[tokio::test]
    async fn out_of_window_returns_unauthorized() {
        let secret = b"secret".to_vec();
        let body = b"{}";
        let input = make_input(&secret, body, 100);

        let uc = ExchangeTokenUseCase::new(FakeNotion::ok(token()), FixedClock(10_000), secret);

        assert!(matches!(
            uc.execute(input).await,
            Err(ExchangeTokenError::Unauthorized("timestamp out of window"))
        ));
    }

    #[tokio::test]
    async fn invalid_json_returns_bad_request() {
        let secret = b"secret".to_vec();
        let body = b"not json";
        let input = make_input(&secret, body, 100);

        let uc = ExchangeTokenUseCase::new(FakeNotion::ok(token()), FixedClock(100), secret);

        assert!(matches!(
            uc.execute(input).await,
            Err(ExchangeTokenError::BadRequest("invalid JSON body"))
        ));
    }

    #[tokio::test]
    async fn empty_code_returns_bad_request() {
        let secret = b"secret".to_vec();
        let body = br#"{"code":"","redirect_uri":"https://x"}"#;
        let input = make_input(&secret, body, 100);

        let uc = ExchangeTokenUseCase::new(FakeNotion::ok(token()), FixedClock(100), secret);

        assert!(matches!(
            uc.execute(input).await,
            Err(ExchangeTokenError::BadRequest("code is required"))
        ));
    }

    #[tokio::test]
    async fn upstream_error_propagates_body() {
        let secret = b"secret".to_vec();
        let body = br#"{"code":"abc","redirect_uri":"https://x"}"#;
        let input = make_input(&secret, body, 100);

        let gateway = FakeNotion::err(NotionError::Upstream {
            status: 401,
            body: "access denied".into(),
        });
        let uc = ExchangeTokenUseCase::new(gateway, FixedClock(100), secret);

        match uc.execute(input).await {
            Err(ExchangeTokenError::UpstreamError { body }) => assert_eq!(body, "access denied"),
            other => panic!("expected UpstreamError, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn network_error_becomes_upstream_unreachable() {
        let secret = b"secret".to_vec();
        let body = br#"{"code":"abc","redirect_uri":"https://x"}"#;
        let input = make_input(&secret, body, 100);

        let gateway = FakeNotion::err(NotionError::Network("dns failure".into()));
        let uc = ExchangeTokenUseCase::new(gateway, FixedClock(100), secret);

        assert!(matches!(
            uc.execute(input).await,
            Err(ExchangeTokenError::UpstreamUnreachable)
        ));
    }
}
