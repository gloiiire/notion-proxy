use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct TokenExchangeRequest {
    pub code: String,
    pub redirect_uri: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NotionToken {
    pub access_token: String,
    pub token_type: String,
    pub bot_id: String,
    pub workspace_id: String,
    pub workspace_name: Option<String>,
    pub workspace_icon: Option<String>,
    pub owner: serde_json::Value,
    pub duplicated_template_id: Option<String>,
    pub request_id: Option<String>,
}
