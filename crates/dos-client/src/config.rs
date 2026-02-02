use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareConfig {
    pub base_url: String,
    pub share: String,
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConfigFile {
    pub shares: Vec<ShareConfig>,
}
