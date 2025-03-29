use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NokyError {
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Bad Request: {0}")]
    BadRequest(String),

    #[error("Not Found: {0}")]
    NotFound(String),

    #[error("Method Not Allowed: {0}")]
    MethodNotAllowed(String),

    #[error("Bad Gateway: {0}")]
    BadGateway(String),

    #[error("Internal Server Error: {0}")]
    InternalServerError(String),
}

impl IntoResponse for NokyError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            NokyError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            NokyError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            NokyError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            NokyError::MethodNotAllowed(msg) => (StatusCode::METHOD_NOT_ALLOWED, msg),
            NokyError::BadGateway(msg) => (StatusCode::BAD_GATEWAY, msg),
            NokyError::InternalServerError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        (status, message).into_response()
    }
}
