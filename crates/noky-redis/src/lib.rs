use eyre::Result;
use noky_store::NonceCache;
use redis::{AsyncCommands, Client};
use serde::Deserialize;
use std::time::Duration;

#[derive(Clone)]
pub struct RedisCache {
    client: Client,
    prefix: String,
}

#[derive(Clone, Deserialize)]
pub struct RedisConfig {
    pub url: String,
    pub key_prefix: String,
}

impl RedisCache {
    pub async fn new(config: RedisConfig) -> Result<Self> {
        Ok(Self {
            client: Client::open(config.url)?,
            prefix: config.key_prefix,
        })
    }

    fn format_key(&self, client_id: &str, nonce: &str) -> String {
        format!("{}:{}:{}", self.prefix, client_id, nonce)
    }
}

impl NonceCache for RedisCache {
    async fn exists(&self, client_id: &str, nonce: &str) -> Result<bool> {
        let key = self.format_key(client_id, nonce);
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let exists: bool = conn.exists(&key).await?;
        Ok(exists)
    }

    async fn store(&self, client_id: &str, nonce: &str, ttl: Duration) -> Result<()> {
        let key = self.format_key(client_id, nonce);
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        conn.set_ex::<_, _, ()>(key, "x", ttl.as_secs()).await?;
        Ok(())
    }
}
