use axum::{http::StatusCode, response::Json};
use serde::Serialize;

use crate::application::exchange_token::ExchangeTokenError;

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

pub type ApiError = (StatusCode, Json<ErrorResponse>);

pub fn err(status: StatusCode, msg: impl Into<String>) -> ApiError {
    (status, Json(ErrorResponse { error: msg.into() }))
}

pub fn map_use_case_error(e: ExchangeTokenError) -> ApiError {
    match e {
        ExchangeTokenError::Unauthorized(msg) => err(StatusCode::UNAUTHORIZED, msg),
        ExchangeTokenError::BadRequest(msg) => err(StatusCode::BAD_REQUEST, msg),
        ExchangeTokenError::UpstreamUnreachable => {
            err(StatusCode::BAD_GATEWAY, "upstream unreachable")
        }
        ExchangeTokenError::UpstreamError { body } => err(StatusCode::BAD_GATEWAY, body),
        ExchangeTokenError::ParseError => err(StatusCode::INTERNAL_SERVER_ERROR, "parse error"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(api: &ApiError) -> &str {
        &api.1 .0.error
    }

    #[test]
    fn unauthorized_maps_to_401() {
        let api = map_use_case_error(ExchangeTokenError::Unauthorized("bad sig"));
        assert_eq!(api.0, StatusCode::UNAUTHORIZED);
        assert_eq!(body(&api), "bad sig");
    }

    #[test]
    fn bad_request_maps_to_400() {
        let api = map_use_case_error(ExchangeTokenError::BadRequest("empty code"));
        assert_eq!(api.0, StatusCode::BAD_REQUEST);
        assert_eq!(body(&api), "empty code");
    }

    #[test]
    fn upstream_unreachable_maps_to_502() {
        let api = map_use_case_error(ExchangeTokenError::UpstreamUnreachable);
        assert_eq!(api.0, StatusCode::BAD_GATEWAY);
        assert_eq!(body(&api), "upstream unreachable");
    }

    #[test]
    fn upstream_error_forwards_body() {
        let api = map_use_case_error(ExchangeTokenError::UpstreamError {
            body: "denied".into(),
        });
        assert_eq!(api.0, StatusCode::BAD_GATEWAY);
        assert_eq!(body(&api), "denied");
    }

    #[test]
    fn parse_error_maps_to_500() {
        let api = map_use_case_error(ExchangeTokenError::ParseError);
        assert_eq!(api.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body(&api), "parse error");
    }
}
