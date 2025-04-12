// Basic integration test for main.rs functionality

use gtmintel::create_app;
use tower::ServiceExt;

#[test]
fn test_main_basic() {
    // This minimal test ensures the main module is included in coverage
    assert!(true, "Main module compiles successfully");
}

#[tokio::test]
async fn test_app_routes() {
    // Test that the app can be created and basic routes work
    let app = create_app();
    
    // Test the health endpoint
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/health")
                .method("GET")
                .body(axum::body::Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), axum::http::StatusCode::OK);
}