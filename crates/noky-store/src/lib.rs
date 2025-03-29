use eyre::Result;
use std::time::Duration;

#[allow(async_fn_in_trait)]
pub trait NonceCache: Send + Sync {
    async fn exists(&self, client_id: &str, nonce: &str) -> Result<bool>;

    async fn store(&self, client_id: &str, nonce: &str, ttl: Duration) -> Result<()>;
}
