use async_trait::async_trait;

use crate::domain::token::NotionToken;

#[derive(Debug)]
pub enum NotionError {
    Network(String),
    Upstream { status: u16, body: String },
    Parse(String),
}

#[async_trait]
pub trait NotionGateway: Send + Sync {
    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
    ) -> Result<NotionToken, NotionError>;
}

pub trait Clock: Send + Sync {
    fn now_unix(&self) -> i64;
}
