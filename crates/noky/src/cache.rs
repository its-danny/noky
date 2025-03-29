use eyre::Result;
use noky_store::NonceCache;
use std::time::Duration;

#[derive(Clone)]
pub enum Cache {
    Redis(noky_redis::RedisCache),
    Moka(noky_moka::MokaCache),
}

impl NonceCache for Cache {
    async fn exists(&self, client_id: &str, nonce: &str) -> Result<bool> {
        match self {
            Cache::Redis(cache) => cache.exists(client_id, nonce).await,
            Cache::Moka(cache) => cache.exists(client_id, nonce).await,
        }
    }

    async fn store(&self, client_id: &str, nonce: &str, ttl: Duration) -> Result<()> {
        match self {
            Cache::Redis(cache) => cache.store(client_id, nonce, ttl).await,
            Cache::Moka(cache) => cache.store(client_id, nonce, ttl).await,
        }
    }
}
