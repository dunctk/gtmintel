use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::Value;
use tower::ServiceExt;
use axum::body::to_bytes;
use axum::extract::connect_info::MockConnectInfo;
use std::net::SocketAddr;

#[tokio::test]
async fn test_research_pages_scale() {
    // Build our application using the correct crate name
    let app = gtmintel::create_app();

    // Create our test request
    let request = Request::builder()
        .uri("/research/pages?domain=scale.com")
        .body(Body::empty())
        .unwrap();

    // Send the request and get response
    let response = app.oneshot(request).await.unwrap();
    
    // Assert status is OK
    assert_eq!(response.status(), StatusCode::OK);

    // Get the response body (with a 1MB size limit)
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    // Assert the response structure and domain
    assert_eq!(json["domain"], "scale.com");
    assert!(json["new_pages_last_7_days"].is_number());
    assert!(json.get("sitemap_url").is_some());
}

#[tokio::test]
async fn test_research_pages_with_sitemap() {
    // Build our application using the correct crate name
    let app = gtmintel::create_app();

    // Test with a domain known to have a sitemap
    let request = Request::builder()
        .uri("/research/pages?domain=rust-lang.org")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["domain"], "rust-lang.org");
    assert!(json["new_pages_last_7_days"].is_number());
    assert!(json.get("sitemap_url").is_some());
    
    // If we found a sitemap, verify it's a valid URL
    if let Some(sitemap_url) = json["sitemap_url"].as_str() {
        assert!(sitemap_url.starts_with("http"));
        assert!(sitemap_url.ends_with(".xml"));
    }
}

#[tokio::test]
async fn test_health_check() {
    // Build our application using the correct crate name
    let app = gtmintel::create_app();

    // Define a mock address
    let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

    // Create our test request
    let request = Request::builder()
        .uri("/health")
        .extension(MockConnectInfo(addr))
        .body(Body::empty())
        .unwrap();

    // Send the request and get response
    let response = app.oneshot(request).await.unwrap();

    // Assert status is OK
    assert_eq!(response.status(), StatusCode::OK);
}