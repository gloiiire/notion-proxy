use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json,
};

use crate::{
    application::exchange_token::ExchangeTokenInput,
    domain::token::NotionToken,
    interface::{
        error::{err, map_use_case_error, ApiError},
        state::AppState,
    },
};

pub async fn exchange_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<NotionToken>, ApiError> {
    let timestamp = headers
        .get("x-pinkha-timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "missing X-Pinkha-Timestamp"))?
        .to_string();

    let nonce = headers
        .get("x-pinkha-nonce")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "missing X-Pinkha-Nonce"))?
        .to_string();

    let signature_hex = headers
        .get("x-pinkha-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "missing X-Pinkha-Signature"))?;

    let signature = hex::decode(signature_hex)
        .map_err(|_| err(StatusCode::UNAUTHORIZED, "invalid signature encoding"))?;

    let input = ExchangeTokenInput {
        timestamp,
        nonce,
        signature,
        body: body.to_vec(),
    };

    let token = state
        .exchange_token
        .execute(input)
        .await
        .map_err(map_use_case_error)?;

    Ok(Json(token))
}
