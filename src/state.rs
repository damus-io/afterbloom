use std::sync::Arc;

use crate::config::Config;
use crate::ratelimit::RateLimiter;
use crate::storage::Storage;

pub struct AppState {
    pub cfg: Config,
    pub storage: Storage,
    pub ratelimit: Arc<RateLimiter>,
}
