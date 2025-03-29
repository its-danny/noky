use eyre::Result;
use moka::future::Cache;
use noky_store::NonceCache;
use serde::Deserialize;
use std::time::{Duration, SystemTime};

#[derive(Clone)]
pub struct MokaCache {
    cache: Cache<String, SystemTime>,
}

#[derive(Clone, Deserialize)]
pub struct MokaConfig {
    pub max_capacity: u64,
    pub ttl: Duration,
}

impl MokaCache {
    pub async fn new(config: MokaConfig) -> Result<Self> {
        let cache = Cache::builder()
            .max_capacity(config.max_capacity)
            .time_to_live(config.ttl)
            .build();

        Ok(Self { cache })
    }
}

impl NonceCache for MokaCache {
    async fn exists(&self, client_id: &str, nonce: &str) -> Result<bool> {
        Ok(self.cache.contains_key(&format!("{}:{}", client_id, nonce)))
    }

    async fn store(&self, client_id: &str, nonce: &str, expiration: Duration) -> Result<()> {
        let key = format!("{}:{}", client_id, nonce);
        let expiry = SystemTime::now() + expiration;

        self.cache.insert(key, expiry).await;

        Ok(())
    }
}
