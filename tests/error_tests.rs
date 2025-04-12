use axum::{
    http::StatusCode,
    response::IntoResponse,
};
use gtmintel::error::AppError;
use http_body_util::BodyExt;
use serde_json::Value;

// Test for AppError Display implementation
#[test]
fn test_app_error_display() {
    // Test each error variant
    let error1 = AppError::SitemapNotFound("example.com".to_string());
    assert_eq!(error1.to_string(), "Sitemap not found for domain: example.com");

    let error2 = AppError::SitemapFetchError("connection timeout".to_string());
    assert_eq!(error2.to_string(), "Error fetching sitemap: connection timeout");

    let error3 = AppError::ProcessingError("invalid XML".to_string());
    assert_eq!(error3.to_string(), "Processing error: invalid XML");

    let error4 = AppError::InvalidRequest("missing domain parameter".to_string());
    assert_eq!(error4.to_string(), "Invalid request: missing domain parameter");
}

// Test for AppError IntoResponse implementation
#[tokio::test]
async fn test_app_error_into_response() {
    // Test SitemapNotFound error
    let error = AppError::SitemapNotFound("example.com".to_string());
    let response = error.into_response();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body["error"], "Sitemap not found for domain: example.com");

    // Test SitemapFetchError error
    let error = AppError::SitemapFetchError("connection timeout".to_string());
    let response = error.into_response();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body["error"], "Error fetching sitemap: connection timeout");

    // Test ProcessingError error
    let error = AppError::ProcessingError("invalid XML".to_string());
    let response = error.into_response();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body["error"], "Processing error: invalid XML");

    // Test InvalidRequest error
    let error = AppError::InvalidRequest("missing domain parameter".to_string());
    let response = error.into_response();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body["error"], "Invalid request: missing domain parameter");
}