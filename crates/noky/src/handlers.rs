use crate::{error::NokyError, AppState};
use axum::extract::ConnectInfo;
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use base64::Engine;
use glob::Pattern;
use noky_store::NonceCache;
use ring::signature::{self, UnparsedPublicKey};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_retry::{
    strategy::{jitter, ExponentialBackoff},
    Retry,
};
use tracing::{error, info, warn};

// GET /health
pub async fn health_check() -> impl IntoResponse {
    StatusCode::OK
}

// ANY /{*wildcard}
pub async fn forward_request(State(state): State<AppState>, request: Request) -> Response {
    let client = reqwest::Client::new();
    let path = request.uri().path().to_string();
    let method = request.method().as_str().to_string();
    let mut headers = request.headers().clone();

    let remote_addr = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|addr| addr.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let (parts, body) = request.into_parts();

    let body = match to_bytes(body, 10 * 1024 * 1024).await {
        Ok(body) => body,
        Err(e) => {
            error!("Failed to read request body: {}", e);
            return NokyError::BadRequest("Failed to read request body".to_string())
                .into_response();
        }
    };

    let service_config = match state.config.services.iter().find(|(_, service)| {
        service
            .routes
            .iter()
            .any(|route| matches_pattern(&route.path, &path))
    }) {
        Some((_, service)) => service,
        None => {
            warn!("Route not found: {} {}", method, path);
            return NokyError::NotFound(format!("Route not found: {} {}", method, path))
                .into_response();
        }
    };

    if let Some(whitelist) = &service_config.whitelist {
        if whitelist.is_empty() {
            return NokyError::IpNotAllowed("No IPs are allowed for this service".to_string())
                .into_response();
        }

        if !whitelist.contains(&remote_addr) {
            return NokyError::IpNotAllowed(format!(
                "IP {} is not allowed for this service",
                remote_addr
            ))
            .into_response();
        }
    }

    let route = service_config
        .routes
        .iter()
        .find(|route| matches_pattern(&route.path, &path))
        // Safety: We know this unwrap is safe because we already found a service with a matching route
        // in the service_config match above. If we found a service, it must have at least one route.
        .unwrap();

    if let Some(methods) = &route.methods {
        if methods.is_empty() || !methods.iter().any(|m| m == &method) {
            warn!("Method not allowed: {} {}", method, path);
            return NokyError::MethodNotAllowed(format!("Method not allowed: {}", method))
                .into_response();
        }
    }

    let session_id = if route.auth {
        match verify_auth(
            &headers,
            &body,
            &method,
            &path,
            service_config,
            &state.cache,
            state.config.cache.expiration,
        )
        .await
        {
            Ok(Some(session_id)) => Some(session_id),
            Ok(None) => {
                return NokyError::Unauthorized("No session ID found".to_string()).into_response()
            }
            Err(e) => return e.into_response(),
        }
    } else {
        None
    };

    if let Some(session_id) = session_id {
        if let Some(client_id) = headers
            .get("X-Auth-Client-ID")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())
        {
            if let Ok(client_id) = client_id.parse() {
                headers.insert("X-Forwarded-Client-ID", client_id);
                if let Ok(value) = HeaderValue::from_str(&session_id) {
                    headers.insert("X-Forwarded-Session-ID", value);
                }
            }
        }
    }

    headers.remove("X-Auth-Client-ID");
    headers.remove("X-Auth-Nonce");
    headers.remove("X-Auth-Signature");

    let retry_strategy = ExponentialBackoff::from_millis(100)
        .max_delay(std::time::Duration::from_secs(2))
        .map(jitter)
        .take(3);

    let reqwest_response = match Retry::spawn(retry_strategy, || async {
        client
            .request(
                method.parse().unwrap(),
                format!("{}{}", service_config.url.trim_end_matches('/'), parts.uri),
            )
            .headers(headers.clone())
            .body(body.clone())
            .send()
            .await
    })
    .await
    {
        Ok(res) => res,
        Err(e) => {
            error!("Upstream request failed after retries: {}", e);
            return NokyError::BadGateway("Upstream request failed".to_string()).into_response();
        }
    };

    let mut response_builder = Response::builder().status(reqwest_response.status());
    if let Some(headers) = response_builder.headers_mut() {
        *headers = reqwest_response.headers().clone();
    }

    match response_builder.body(Body::from_stream(reqwest_response.bytes_stream())) {
        Ok(response) => {
            info!("Request forwarded successfully: {} {}", method, path);
            response
        }
        Err(e) => {
            error!("Failed to build response: {}", e);
            NokyError::InternalServerError("Failed to build response".to_string()).into_response()
        }
    }
}

fn matches_pattern(pattern: &str, path: &str) -> bool {
    Pattern::new(pattern)
        .map(|p| p.matches(path))
        .unwrap_or(false)
}

async fn verify_auth(
    headers: &axum::http::HeaderMap,
    body: &[u8],
    method: &str,
    path: &str,
    service_config: &crate::config::ServiceConfig,
    cache: &impl NonceCache,
    expiration: std::time::Duration,
) -> Result<Option<String>, NokyError> {
    let client_id = headers
        .get("X-Auth-Client-ID")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            NokyError::Unauthorized("Invalid or missing client ID header".to_string())
        })?;

    let nonce = headers
        .get("X-Auth-Nonce")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| NokyError::Unauthorized("Invalid or missing nonce header".to_string()))?;

    let signature = headers
        .get("X-Auth-Signature")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            NokyError::Unauthorized("Invalid or missing signature header".to_string())
        })?;

    let parts: Vec<&str> = nonce.split(':').collect();
    if parts.len() != 3 {
        return Err(NokyError::Unauthorized("Invalid nonce format".to_string()));
    }

    let (session_id, timestamp, _) = (parts[0], parts[1], parts[2]);
    let timestamp = timestamp
        .parse::<u64>()
        .map_err(|_| NokyError::Unauthorized("Invalid timestamp in nonce".to_string()))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| NokyError::InternalServerError("System time error".to_string()))?
        .as_secs();

    let window = expiration.as_secs();
    if timestamp < now.saturating_sub(window) || timestamp > now.saturating_add(window) {
        return Err(NokyError::Unauthorized("Nonce expired".to_string()));
    }

    let nonce_key = format!("{}:{}:{}", client_id, session_id, nonce);
    if cache.exists(client_id, &nonce_key).await.map_err(|e| {
        error!("Cache error: {}", e);
        NokyError::InternalServerError("Cache error".to_string())
    })? {
        return Err(NokyError::Unauthorized("Nonce already used".to_string()));
    }

    cache
        .store(client_id, &nonce_key, expiration)
        .await
        .map_err(|e| {
            error!("Cache error: {}", e);
            NokyError::InternalServerError("Cache error".to_string())
        })?;

    let public_key = service_config
        .keys
        .iter()
        .find(|k| k.id == client_id)
        .map(|k| &k.key)
        .ok_or_else(|| NokyError::Unauthorized(format!("Client ID not found: {}", client_id)))?;

    let public_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(public_key)
        .map_err(|e| NokyError::Unauthorized(format!("Invalid public key format: {}", e)))?;

    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature)
        .map_err(|e| NokyError::Unauthorized(format!("Invalid signature format: {}", e)))?;

    let body_hash = format!("{:x}", Sha256::digest(body));
    let message = format!("{}{}{}{}", method, path, nonce, body_hash);
    let key = UnparsedPublicKey::new(&signature::ED25519, public_key_bytes);

    key.verify(message.as_bytes(), &signature_bytes)
        .map_err(|e| {
            error!("Signature verification failed: {}", e);
            NokyError::Unauthorized("Signature verification failed".to_string())
        })?;

    info!("Request authenticated: {} {}", method, path);

    Ok(Some(session_id.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cache::Cache,
        config::{Config, KeyConfig, RouteConfig, ServiceConfig},
    };
    use axum::http::{HeaderMap, Uri};
    use noky_moka::{MokaCache, MokaConfig};
    use rand::Rng;
    use reqwest::Method;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use wiremock::{
        matchers::{header_exists, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    fn sign_request(
        client_id: &str,
        private_key: &[u8],
        method: &str,
        path: &str,
        body: &[u8],
    ) -> HeaderMap {
        let mut headers = HeaderMap::new();

        let session_id = "test-session-id";
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let random = rand::rng()
            .sample_iter(&rand::distr::Alphanumeric)
            .take(16)
            .map(char::from)
            .collect::<String>();

        let nonce = format!("{}:{}:{}", session_id, timestamp, random);
        let body_hash = format!("{:x}", Sha256::digest(body));
        let message = format!("{}{}{}{}", method, path, nonce, body_hash);

        let key_pair = Ed25519KeyPair::from_pkcs8(private_key).unwrap();
        let signature = key_pair.sign(message.as_bytes());
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.as_ref());

        headers.insert("X-Auth-Client-ID", client_id.parse().unwrap());
        headers.insert("X-Auth-Nonce", nonce.parse().unwrap());
        headers.insert("X-Auth-Signature", signature_b64.parse().unwrap());

        headers
    }

    struct TestKeys {
        private_key: Vec<u8>,
        public_key: String,
    }

    fn create_test_keys() -> TestKeys {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
        let public_key =
            base64::engine::general_purpose::STANDARD.encode(key_pair.public_key().as_ref());

        TestKeys {
            private_key: pkcs8_bytes.as_ref().to_vec(),
            public_key,
        }
    }

    fn create_test_config(keys: &TestKeys) -> Config {
        Config {
            server: crate::config::Server {
                address: "127.0.0.1".to_string(),
                port: 8080,
            },
            cache: crate::config::Cache {
                expiration: std::time::Duration::from_secs(3600),
                provider: None,
            },
            logging: crate::config::LoggingConfig {
                level: "debug".to_string(),
            },
            services: HashMap::from([(
                "test".to_string(),
                ServiceConfig {
                    url: "http://test-service".to_string(),
                    routes: vec![
                        RouteConfig {
                            path: "/api/*".to_string(),
                            methods: Some(vec!["GET".to_string()]),
                            auth: true,
                        },
                        RouteConfig {
                            path: "/public/*".to_string(),
                            methods: Some(vec!["GET".to_string()]),
                            auth: false,
                        },
                    ],
                    keys: vec![KeyConfig {
                        id: "test-client".to_string(),
                        key: keys.public_key.clone(),
                    }],
                    whitelist: None,
                },
            )]),
        }
    }

    fn create_test_request(
        path: &str,
        method: Method,
        body: &str,
        headers: Option<HeaderMap>,
    ) -> Request {
        let uri = Uri::builder().path_and_query(path).build().unwrap();

        let mut builder = Request::builder().uri(uri).method(method);

        if let Some(hdrs) = headers {
            for (name, value) in hdrs.iter() {
                builder = builder.header(name, value);
            }
        }

        builder.body(Body::from(body.to_string())).unwrap()
    }

    fn create_signed_request(
        path: &str,
        method: Method,
        body: &str,
        client_id: &str,
        private_key: &[u8],
        extra_headers: Option<HeaderMap>,
    ) -> Request {
        let mut auth_headers = sign_request(
            client_id,
            private_key,
            method.as_str(),
            path,
            body.as_bytes(),
        );

        if let Some(extra) = extra_headers {
            for (name, value) in extra.iter() {
                auth_headers.insert(name.clone(), value.clone());
            }
        }

        create_test_request(path, method, body, Some(auth_headers))
    }

    #[tokio::test]
    async fn test_route_not_found() {
        let keys = create_test_keys();
        let config = create_test_config(&keys);
        let state = AppState {
            config,
            cache: Cache::Moka(
                MokaCache::new(MokaConfig {
                    max_capacity: 1000,
                    ttl: std::time::Duration::from_secs(3600),
                })
                .await
                .unwrap(),
            ),
        };

        let request = create_test_request("/unknown", Method::GET, "test", None);
        let response = forward_request(State(state), request).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_unauthorized() {
        let keys = create_test_keys();
        let config = create_test_config(&keys);
        let state = AppState {
            config,
            cache: Cache::Moka(
                MokaCache::new(MokaConfig {
                    max_capacity: 1000,
                    ttl: std::time::Duration::from_secs(3600),
                })
                .await
                .unwrap(),
            ),
        };

        let request = create_test_request("/api/test", Method::GET, "test", None);
        let response = forward_request(State(state), request).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_authorized() {
        let keys = create_test_keys();
        let config = create_test_config(&keys);
        let state = AppState {
            config,
            cache: Cache::Moka(
                MokaCache::new(MokaConfig {
                    max_capacity: 1000,
                    ttl: std::time::Duration::from_secs(3600),
                })
                .await
                .unwrap(),
            ),
        };

        let request = create_signed_request(
            "/api/test",
            Method::GET,
            "test",
            "test-client",
            &keys.private_key,
            None,
        );

        let response = forward_request(State(state), request).await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn test_public_route() {
        let keys = create_test_keys();
        let config = create_test_config(&keys);
        let state = AppState {
            config,
            cache: Cache::Moka(
                MokaCache::new(MokaConfig {
                    max_capacity: 1000,
                    ttl: std::time::Duration::from_secs(3600),
                })
                .await
                .unwrap(),
            ),
        };

        let request = create_test_request("/public/test", Method::GET, "test", None);
        let response = forward_request(State(state), request).await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn test_wildcard_matching() {
        let keys = create_test_keys();
        let config = create_test_config(&keys);
        let state = AppState {
            config,
            cache: Cache::Moka(
                MokaCache::new(MokaConfig {
                    max_capacity: 1000,
                    ttl: std::time::Duration::from_secs(3600),
                })
                .await
                .unwrap(),
            ),
        };

        let request = create_signed_request(
            "/api/test/subpath",
            Method::GET,
            "test",
            "test-client",
            &keys.private_key,
            None,
        );

        let response = forward_request(State(state), request).await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn test_method_not_allowed() {
        let keys = create_test_keys();
        let config = create_test_config(&keys);
        let state = AppState {
            config,
            cache: Cache::Moka(
                MokaCache::new(MokaConfig {
                    max_capacity: 1000,
                    ttl: std::time::Duration::from_secs(3600),
                })
                .await
                .unwrap(),
            ),
        };

        let request = create_signed_request(
            "/api/test",
            Method::POST,
            "test",
            "test-client",
            &keys.private_key,
            None,
        );

        let response = forward_request(State(state), request).await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn test_all_methods_allowed() {
        let keys = create_test_keys();
        let mut config = create_test_config(&keys);
        config.services.get_mut("test").unwrap().routes[0].methods = None;

        let state = AppState {
            config,
            cache: Cache::Moka(
                MokaCache::new(MokaConfig {
                    max_capacity: 1000,
                    ttl: std::time::Duration::from_secs(3600),
                })
                .await
                .unwrap(),
            ),
        };

        for method in [Method::GET, Method::POST, Method::PUT, Method::DELETE] {
            let request = create_signed_request(
                "/api/test",
                method.clone(),
                "test",
                "test-client",
                &keys.private_key,
                None,
            );

            let response = forward_request(State(state.clone()), request).await;
            assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        }
    }

    #[tokio::test]
    async fn test_no_methods_allowed() {
        let keys = create_test_keys();
        let mut config = create_test_config(&keys);
        config.services.get_mut("test").unwrap().routes[0].methods = Some(vec![]);

        let state = AppState {
            config,
            cache: Cache::Moka(
                MokaCache::new(MokaConfig {
                    max_capacity: 1000,
                    ttl: std::time::Duration::from_secs(3600),
                })
                .await
                .unwrap(),
            ),
        };

        for method in [Method::GET, Method::POST, Method::PUT, Method::DELETE] {
            let request = create_signed_request(
                "/api/test",
                method.clone(),
                "test",
                "test-client",
                &keys.private_key,
                None,
            );

            let response = forward_request(State(state.clone()), request).await;
            assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        }
    }

    #[tokio::test]
    async fn test_header_forwarding() {
        let mock_server = MockServer::start().await;

        let keys = create_test_keys();
        let mut config = create_test_config(&keys);
        config.services.get_mut("test").unwrap().url = mock_server.uri();

        let state = AppState {
            config,
            cache: Cache::Moka(
                MokaCache::new(MokaConfig {
                    max_capacity: 1000,
                    ttl: std::time::Duration::from_secs(3600),
                })
                .await
                .unwrap(),
            ),
        };

        Mock::given(method("GET"))
            .and(path("/api/test"))
            .and(header_exists("X-Forwarded-Client-ID"))
            .and(header_exists("Content-Type"))
            .and(header_exists("User-Agent"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut extra_headers = HeaderMap::new();
        extra_headers.insert("Content-Type", "application/json".parse().unwrap());
        extra_headers.insert("User-Agent", "test-agent".parse().unwrap());

        let request = create_signed_request(
            "/api/test",
            Method::GET,
            "test",
            "test-client",
            &keys.private_key,
            Some(extra_headers),
        );

        let response = forward_request(State(state), request).await;

        assert_eq!(response.status(), StatusCode::OK);

        assert!(!response.headers().contains_key("X-Auth-Client-ID"));
        assert!(!response.headers().contains_key("X-Auth-Nonce"));
        assert!(!response.headers().contains_key("X-Auth-Signature"));
        assert!(!response.headers().contains_key("X-Auth-Body-Hash"));
    }

    #[tokio::test]
    async fn test_body_hash_verification() {
        let keys = create_test_keys();
        let config = create_test_config(&keys);
        let state = AppState {
            config,
            cache: Cache::Moka(
                MokaCache::new(MokaConfig {
                    max_capacity: 1000,
                    ttl: std::time::Duration::from_secs(3600),
                })
                .await
                .unwrap(),
            ),
        };

        let original_body = "original content";
        let auth_headers = sign_request(
            "test-client",
            &keys.private_key,
            "GET",
            "/api/test",
            original_body.as_bytes(),
        );

        let request = create_test_request(
            "/api/test",
            Method::GET,
            "tampered content",
            Some(auth_headers),
        );

        let response = forward_request(State(state), request).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_ip_whitelist() {
        let keys = create_test_keys();
        let mut config = create_test_config(&keys);
        config.services.get_mut("test").unwrap().whitelist = Some(vec!["127.0.0.1".to_string()]);
        let state = AppState {
            config,
            cache: Cache::Moka(
                MokaCache::new(MokaConfig {
                    max_capacity: 1000,
                    ttl: std::time::Duration::from_secs(3600),
                })
                .await
                .unwrap(),
            ),
        };

        let mut request = create_test_request("/public/test", Method::GET, "test", None);
        request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            "127.0.0.1".parse().unwrap(),
            8080,
        )));
        let response = forward_request(State(state.clone()), request).await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

        let mut request = create_test_request("/public/test", Method::GET, "test", None);
        request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            "192.168.1.1".parse().unwrap(),
            8080,
        )));
        let response = forward_request(State(state.clone()), request).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mut config = create_test_config(&keys);
        config.services.get_mut("test").unwrap().whitelist = Some(vec![]);
        let state = AppState {
            config,
            cache: Cache::Moka(
                MokaCache::new(MokaConfig {
                    max_capacity: 1000,
                    ttl: std::time::Duration::from_secs(3600),
                })
                .await
                .unwrap(),
            ),
        };
        let mut request = create_test_request("/public/test", Method::GET, "test", None);
        request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            "127.0.0.1".parse().unwrap(),
            8080,
        )));
        let response = forward_request(State(state), request).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let config = create_test_config(&keys);
        let state = AppState {
            config,
            cache: Cache::Moka(
                MokaCache::new(MokaConfig {
                    max_capacity: 1000,
                    ttl: std::time::Duration::from_secs(3600),
                })
                .await
                .unwrap(),
            ),
        };
        let mut request = create_test_request("/public/test", Method::GET, "test", None);
        request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            "192.168.1.1".parse().unwrap(),
            8080,
        )));
        let response = forward_request(State(state), request).await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }
}
