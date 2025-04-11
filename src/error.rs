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
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::SitemapNotFound(domain) => write!(f, "Sitemap not found for domain: {}", domain),
            AppError::SitemapFetchError(msg) => write!(f, "Error fetching sitemap: {}", msg),
            AppError::ProcessingError(msg) => write!(f, "Processing error: {}", msg),
            AppError::InvalidRequest(msg) => write!(f, "Invalid request: {}", msg),
        }
    }
}

impl std::error::Error for AppError {}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            AppError::SitemapNotFound(_) => (StatusCode::UNPROCESSABLE_ENTITY, self.to_string()),
            AppError::SitemapFetchError(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::ProcessingError(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::InvalidRequest(_) => (StatusCode::UNPROCESSABLE_ENTITY, self.to_string()),
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
} 