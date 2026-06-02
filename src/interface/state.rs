use std::sync::Arc;

use crate::application::exchange_token::ExchangeTokenPort;

#[derive(Clone)]
pub struct AppState {
    pub exchange_token: Arc<dyn ExchangeTokenPort>,
}
