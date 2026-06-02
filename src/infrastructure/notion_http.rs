use async_trait::async_trait;
use reqwest::Client;

use crate::domain::{
    ports::{NotionError, NotionGateway},
    token::NotionToken,
};

pub struct NotionHttpGateway {
    http: Client,
    base_url: String,
    client_id: String,
    client_secret: String,
}

impl NotionHttpGateway {
    pub fn new(http: Client, base_url: String, client_id: String, client_secret: String) -> Self {
        Self {
            http,
            base_url,
            client_id,
            client_secret,
        }
    }
}

#[async_trait]
impl NotionGateway for NotionHttpGateway {
    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
    ) -> Result<NotionToken, NotionError> {
        let url = format!("{}/v1/oauth/token", self.base_url);
        let response = self
            .http
            .post(&url)
            .basic_auth(&self.client_id, Some(&self.client_secret))
            .header("Notion-Version", "2022-06-28")
            .json(&serde_json::json!({
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
            }))
            .send()
            .await
            .map_err(|e| NotionError::Network(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(NotionError::Upstream { status, body });
        }

        response
            .json::<NotionToken>()
            .await
            .map_err(|e| NotionError::Parse(e.to_string()))
    }
}
