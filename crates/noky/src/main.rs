mod cache;
mod config;
mod error;
mod handlers;

use std::path::PathBuf;
use std::str::FromStr;

use crate::config::Config;
use axum::{
    routing::{any, get},
    Router,
};
use cache::Cache;
use clap::{command, Parser};
use config::CacheProvider;
use eyre::Result;
use handlers::{forward_request, health_check};
use noky_moka::{MokaCache, MokaConfig};
use noky_redis::RedisCache;
use tracing_subscriber::{filter::LevelFilter, FmtSubscriber};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    config: Option<PathBuf>,
}

#[derive(Clone)]
struct AppState {
    config: Config,
    cache: Cache,
}

fn setup_app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/{*wildcard}", any(forward_request))
        .with_state(state)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config = Config::load(args.config)?;
    let config_clone = config.clone();

    FmtSubscriber::builder()
        .with_max_level(LevelFilter::from_str(&config.logging.level)?)
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_ansi(true)
        .init();

    let cache = match config.cache.provider {
        Some(CacheProvider::Redis(config)) => Cache::Redis(RedisCache::new(config).await?),
        Some(CacheProvider::Moka(config)) => Cache::Moka(MokaCache::new(config).await?),
        None => Cache::Moka(
            MokaCache::new(MokaConfig {
                max_capacity: 1000,
                ttl: std::time::Duration::from_secs(3600),
            })
            .await?,
        ),
    };

    let state = AppState {
        config: config_clone,
        cache,
    };

    let address = format!("{}:{}", config.server.address, config.server.port);
    let listener = tokio::net::TcpListener::bind(address).await?;
    let app = setup_app(state);

    axum::serve(listener, app).await?;

    Ok(())
}
