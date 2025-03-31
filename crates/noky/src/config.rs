use std::time::Duration;
use std::{collections::HashMap, path::PathBuf};

use eyre::{eyre, Result};
use figment::{
    providers::{Env, Format, Json, Toml, Yaml},
    Figment,
};
use humantime::parse_duration;
use noky_moka::MokaConfig;
use noky_redis::RedisConfig;
use serde::Deserialize;

#[derive(Clone, Deserialize)]
pub struct Config {
    pub server: Server,
    pub cache: Cache,
    pub logging: LoggingConfig,
    pub services: HashMap<String, ServiceConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: Server {
                address: "0.0.0.0".to_string(),
                port: 3000,
            },
            cache: Cache {
                expiration: Duration::from_secs(3600),
                provider: None,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
            },
            services: HashMap::new(),
        }
    }
}

#[derive(Clone, Deserialize)]
pub struct Server {
    pub address: String,
    pub port: u16,
}

#[derive(Clone, Deserialize)]
pub struct Cache {
    #[serde(deserialize_with = "deserialize_duration")]
    pub expiration: Duration,
    pub provider: Option<CacheProvider>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheProvider {
    Redis(RedisConfig),
    Moka(MokaConfig),
}

#[derive(Clone, Deserialize)]
pub struct ServiceConfig {
    pub url: String,
    pub routes: Vec<RouteConfig>,
    pub keys: Vec<KeyConfig>,
    pub whitelist: Option<Vec<String>>,
}

#[derive(Clone, Deserialize)]
pub struct RouteConfig {
    pub path: String,
    pub methods: Option<Vec<String>>,
    pub auth: bool,
}

#[derive(Clone, Deserialize)]
pub struct KeyConfig {
    pub id: String,
    pub key: String,
}

#[derive(Clone, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
        }
    }
}

impl Config {
    pub fn load(path: Option<PathBuf>) -> Result<Self> {
        let config_dir = dirs::config_dir().ok_or(eyre!("Config directory not found"))?;

        let mut figment = Figment::new()
            .merge(Toml::file(config_dir.join("noky.toml")))
            .merge(Json::file(config_dir.join("noky.json")))
            .merge(Yaml::file(config_dir.join("noky.yaml")));

        if let Some(path) = path {
            let extension = path
                .extension()
                .and_then(|ext| ext.to_str())
                .ok_or_else(|| eyre!("Invalid file extension"))?;

            match extension {
                "toml" => figment = figment.merge(Toml::file(path)),
                "json" => figment = figment.merge(Json::file(path)),
                "yaml" | "yml" => figment = figment.merge(Yaml::file(path)),
                _ => {
                    return Err(eyre!(
                        "Unsupported config file format. Supported formats are: toml, json, yaml"
                    ))
                }
            }
        }

        figment = figment.merge(Env::prefixed("NOKY_"));

        let config: Config = figment.extract()?;

        Ok(config)
    }
}

pub fn deserialize_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    use serde_json::Value;

    let value = Value::deserialize(deserializer)?;

    match value {
        Value::String(s) => parse_duration(&s).map_err(Error::custom),
        Value::Number(n) if n.is_u64() => Ok(Duration::from_secs(n.as_u64().unwrap())),
        Value::Number(n) if n.is_f64() => Ok(Duration::from_secs_f64(n.as_f64().unwrap())),
        _ => Err(Error::custom("expected a string or number for duration")),
    }
}
