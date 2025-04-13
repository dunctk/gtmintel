use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::fmt;

#[derive(Debug)]
pub enum AppError {
    SitemapNotFound(String),
    SitemapFetchError(String),
    ProcessingError(String),
    InvalidRequest(String),
    SerializationError(String),
    UnprocessableEntity(String),
    InternalError(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::SitemapNotFound(domain) => write!(f, "Sitemap not found for domain: {}", domain),
            AppError::SitemapFetchError(msg) => write!(f, "Error fetching/processing sitemap: {}", msg),
            AppError::ProcessingError(msg) => write!(f, "Processing error: {}", msg),
            AppError::InvalidRequest(msg) => write!(f, "Invalid request: {}", msg),
            AppError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            AppError::UnprocessableEntity(msg) => write!(f, "Unprocessable Entity: {}", msg),
            AppError::InternalError(msg) => write!(f, "Internal Server Error: {}", msg),
        }
    }
}

impl std::error::Error for AppError {}

// Add implementation for From<serde_json::Error>
impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::SerializationError(err.to_string())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            AppError::SitemapNotFound(_) => (StatusCode::UNPROCESSABLE_ENTITY, self.to_string()),
            AppError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::UnprocessableEntity(_) => (StatusCode::UNPROCESSABLE_ENTITY, self.to_string()),
            AppError::SitemapFetchError(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::ProcessingError(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::SerializationError(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::InternalError(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
} 