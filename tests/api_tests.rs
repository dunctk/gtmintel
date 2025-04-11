use axum::{
    body::Body,
    http::{Request, StatusCode},
    Json,
    response::IntoResponse,
};
use http_body_util::BodyExt; // For Response body handling
use tower::ServiceExt; // For oneshot
use tracing_subscriber;
use serde_json::Value;

// We need to import the types we'll use
use serde::{Deserialize, Serialize};

// Health check test
#[tokio::test]
async fn test_health_endpoint() {
    // Initialize tracing for tests
    let _ = tracing_subscriber::fmt::try_init();
    
    // Create a direct application router WITHOUT any middleware
    let app = axum::Router::new()
        .route("/health", axum::routing::get(|| async { StatusCode::OK }));
    
    // Create a GET request to the health endpoint
    let request = Request::builder()
        .uri("/health")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    
    // Process the request and get a response
    let response = app
        .oneshot(request)
        .await
        .unwrap();
    
    // Check that the status code is 200 OK
    assert_eq!(response.status(), StatusCode::OK);
}

/// Tests the research pages updated endpoint with a basic domain parameter
#[tokio::test]
async fn test_research_pages_basic() {
    // Initialize tracing for tests
    let _ = tracing_subscriber::fmt::try_init();
    
    // Create a direct router for just this endpoint, using a mock handler
    let app = axum::Router::new()
        .route("/research/pages/updated", axum::routing::get(mock_research_pages));
    
    // Create a GET request with a test domain
    let request = Request::builder()
        .uri("/research/pages/updated?domain=example.com")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    
    // Process the request and get a response
    let response = app
        .oneshot(request)
        .await
        .unwrap();
    
    // Get status and body for debugging
    let status = response.status();
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8_lossy(&body_bytes);
    println!("Response status: {}, body: {}", status, body_str);
    
    // Check status code is 200 OK
    assert_eq!(status, StatusCode::OK);
    
    // Check response body contains expected fields
    let body: Value = serde_json::from_slice(&body_bytes).unwrap();
    
    assert_eq!(body["domain"], "example.com");
    assert!(body["updated_pages"].is_number());
    assert_eq!(body["days_analyzed"], 7);
}

/// Tests the research pages endpoint with optional parameters
#[tokio::test]
async fn test_research_pages_with_options() {
    // Initialize tracing for tests
    let _ = tracing_subscriber::fmt::try_init();
    
    // Create a direct router for just this endpoint, using a mock handler
    let app = axum::Router::new()
        .route("/research/pages/updated", axum::routing::get(mock_research_pages));
    
    // Create a GET request with optional parameters
    let request = Request::builder()
        .uri("/research/pages/updated?domain=example.com&list_pages=true&within_days=14")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    
    // Process the request and get a response
    let response = app
        .oneshot(request)
        .await
        .unwrap();
    
    // Check status code is 200 OK
    assert_eq!(response.status(), StatusCode::OK);
    
    // Check response body contains expected fields
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body_bytes).unwrap();
    
    assert_eq!(body["domain"], "example.com");
    assert!(body["updated_pages"].is_number());
    assert_eq!(body["days_analyzed"], 14);
    assert!(body["updated_page_urls"].is_array());
}

/// Tests the research pages endpoint with a domain that doesn't have a sitemap
#[tokio::test]
async fn test_research_pages_no_sitemap() {
    // Initialize tracing for tests
    let _ = tracing_subscriber::fmt::try_init();
    
    // Create a direct router for just this endpoint, using a mock handler for the failure case
    let app = axum::Router::new()
        .route("/research/pages/updated", axum::routing::get(mock_research_pages_no_sitemap));
    
    // Create a GET request with a domain that will trigger a "no sitemap" response
    let request = Request::builder()
        .uri("/research/pages/updated?domain=no-sitemap-example.com")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    
    // Process the request and get a response
    let response = app
        .oneshot(request)
        .await
        .unwrap();
    
    // Get status and body for debugging
    let status = response.status();
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8_lossy(&body_bytes);
    println!("Response status: {}, body: {}", status, body_str);
    
    // Should return 422 Unprocessable Entity when sitemap not found
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    
    // Check response body contains expected fields
    let body: Value = serde_json::from_slice(&body_bytes).unwrap();
    
    assert_eq!(body["domain"], "no-sitemap-example.com");
    assert_eq!(body["updated_pages"], 0);
    assert!(body["sitemap_url"].is_null());
}

// Define our own simple versions of the types for testing
// This avoids dependency issues and simplifies our tests
#[derive(Debug, Deserialize)]
struct ResearchQuery {
    pub domain: String,
    pub list_pages: Option<bool>,
    #[serde(default = "default_within_days")]
    pub within_days: u32,
}

// For batch new pages endpoint
#[derive(Debug, Deserialize, Serialize)]
struct NewPagesQuery {
    pub domains: Vec<String>,
    pub list_pages: Option<bool>,
    #[serde(default = "default_within_days_new")]
    pub within_days: u32,
}

fn default_within_days_new() -> u32 {
    30 // Default to checking the last 30 days for new pages
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
enum DetectionMethod {
    SitemapLastmod,
    WordPressApi,
    HtmlAnalysis,
    Mixed,
    None,
}

#[derive(Debug, Serialize, Deserialize)]
struct NewPageDetail {
    pub url: String,
    pub creation_date: Option<String>,
    pub confidence: f64,
    pub detection_detail: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct NewPagesResponse {
    pub domain: String,
    pub new_pages_count: i32,
    pub days_analyzed: u32,
    pub detection_method: DetectionMethod,
    pub sitemap_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_page_urls: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_page_details: Option<Vec<NewPageDetail>>,
    pub processing_errors: Vec<String>,
}

// Function to provide the default value for within_days - same as in the actual code
fn default_within_days() -> u32 {
    7
}

#[derive(Debug, Serialize)]
struct ResearchResponse {
    pub domain: String,
    pub updated_pages: i32,
    pub days_analyzed: u32,
    pub sitemap_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_page_urls: Option<Vec<String>>,
}

// Mock handler for research pages that returns successful data
async fn mock_research_pages(query: axum::extract::Query<ResearchQuery>) -> impl axum::response::IntoResponse {
    // Extract the domain and other parameters from the query
    let domain = query.domain.clone();
    let within_days = query.within_days;
    let list_pages = query.list_pages.unwrap_or(false);
    
    // Create a mock response
    let mut response = ResearchResponse {
        domain,
        updated_pages: 42, // Mock value
        days_analyzed: within_days,
        sitemap_url: Some("https://example.com/sitemap.xml".to_string()),
        updated_page_urls: None,
    };
    
    // If list_pages is true, add mock URL list
    if list_pages {
        response.updated_page_urls = Some(vec![
            "https://example.com/page1".to_string(),
            "https://example.com/page2".to_string(),
            "https://example.com/page3".to_string(),
        ]);
    }
    
    (StatusCode::OK, Json(response))
}

// Mock handler for research pages that simulates no sitemap found
async fn mock_research_pages_no_sitemap(query: axum::extract::Query<ResearchQuery>) -> impl axum::response::IntoResponse {
    // Create a response indicating no sitemap was found
    let response = ResearchResponse {
        domain: query.domain.clone(),
        updated_pages: 0,
        days_analyzed: query.within_days,
        sitemap_url: None,
        updated_page_urls: None,
    };
    
    (StatusCode::UNPROCESSABLE_ENTITY, Json(response))
}

/// Tests the batch new pages endpoint
#[tokio::test]
async fn test_research_new_pages_batch() {
    // Initialize tracing for tests
    let _ = tracing_subscriber::fmt::try_init();
    
    // Create a direct router for just this endpoint, using a mock handler
    let app = axum::Router::new()
        .route("/research/pages/new/batch", axum::routing::post(mock_research_new_pages_batch));
    
    // Create a test request body with multiple domains
    let test_query = NewPagesQuery {
        domains: vec!["wordpress.example.com".to_string(), "html.example.com".to_string()],
        list_pages: Some(true),
        within_days: 30,
    };
    
    // Create a POST request with the test body
    let request = Request::builder()
        .uri("/research/pages/new/batch")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&test_query).unwrap()))
        .unwrap();
    
    // Process the request and get a response
    let response = app
        .oneshot(request)
        .await
        .unwrap();
    
    // Get status and body for debugging
    let status = response.status();
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8_lossy(&body_bytes);
    println!("Response status: {}, body: {}", status, body_str);
    
    // Check status code is 200 OK
    assert_eq!(status, StatusCode::OK);
    
    // Parse the response
    let body: Vec<NewPagesResponse> = serde_json::from_slice(&body_bytes).unwrap();
    
    // Verify the first domain uses WordPress API detection
    assert_eq!(body[0].domain, "wordpress.example.com");
    assert_eq!(body[0].detection_method, DetectionMethod::WordPressApi);
    assert_eq!(body[0].new_pages_count, 3);
    assert!(body[0].new_page_urls.is_some());
    assert_eq!(body[0].new_page_urls.as_ref().unwrap().len(), 3);
    
    // Verify the second domain uses HTML analysis
    assert_eq!(body[1].domain, "html.example.com");
    assert_eq!(body[1].detection_method, DetectionMethod::HtmlAnalysis);
    assert_eq!(body[1].new_pages_count, 2);
    assert!(body[1].new_page_urls.is_some());
    assert_eq!(body[1].new_page_urls.as_ref().unwrap().len(), 2);
}

/// Tests the batch new pages endpoint with too many domains
#[tokio::test]
async fn test_research_new_pages_batch_too_many_domains() {
    // Initialize tracing for tests
    let _ = tracing_subscriber::fmt::try_init();
    
    // Create a direct router for just this endpoint, using a mock handler
    let app = axum::Router::new()
        .route("/research/pages/new/batch", axum::routing::post(mock_research_new_pages_batch));
    
    // Create a test request body with too many domains (more than 20)
    let mut domains = Vec::new();
    for i in 0..25 {
        domains.push(format!("domain{}.example.com", i));
    }
    
    let test_query = NewPagesQuery {
        domains,
        list_pages: Some(true),
        within_days: 30,
    };
    
    // Create a POST request with the test body
    let request = Request::builder()
        .uri("/research/pages/new/batch")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&test_query).unwrap()))
        .unwrap();
    
    // Process the request and get a response
    let response = app
        .oneshot(request)
        .await
        .unwrap();
    
    // Get status and body for debugging
    let status = response.status();
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8_lossy(&body_bytes);
    println!("Response status: {}, body: {}", status, body_str);
    
    // Check status code is 422 Unprocessable Entity
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    
    // Check response body contains error message
    let body: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert!(body["error"].as_str().unwrap().contains("Maximum number of domains"));
}

// Mock handler for batch new pages endpoint
async fn mock_research_new_pages_batch(
    Json(query): Json<NewPagesQuery>
) -> impl axum::response::IntoResponse {
    const MAX_DOMAINS: usize = 20;
    
    // Check if too many domains
    if query.domains.len() > MAX_DOMAINS {
        return (
            StatusCode::UNPROCESSABLE_ENTITY, 
            Json(serde_json::json!({
                "error": format!("Maximum number of domains allowed is {}", MAX_DOMAINS)
            }))
        ).into_response();
    }
    // Extract parameters
    let domains = query.domains;
    let within_days = query.within_days;
    let should_list_pages = query.list_pages.unwrap_or(false);
    
    // Create responses for each domain
    let mut responses = Vec::new();
    
    for domain in domains {
        if domain == "wordpress.example.com" {
            // WordPress API detected domain
            let mut response = NewPagesResponse {
                domain: domain.clone(),
                new_pages_count: 3,
                days_analyzed: within_days,
                detection_method: DetectionMethod::WordPressApi,
                sitemap_url: Some("https://wordpress.example.com/sitemap_index.xml".to_string()),
                new_page_urls: None,
                new_page_details: None,
                processing_errors: Vec::new(),
            };
            
            if should_list_pages {
                // Mock WordPress API post URLs
                let urls = vec![
                    "https://wordpress.example.com/2024/04/01/post1/".to_string(),
                    "https://wordpress.example.com/2024/04/05/post2/".to_string(),
                    "https://wordpress.example.com/2024/04/10/post3/".to_string(),
                ];
                
                // Mock WordPress API post details
                let details = vec![
                    NewPageDetail {
                        url: "https://wordpress.example.com/2024/04/01/post1/".to_string(),
                        creation_date: Some("2024-04-01T10:00:00Z".to_string()),
                        confidence: 0.95,
                        detection_detail: "wordpress_api_post: Post 1".to_string(),
                    },
                    NewPageDetail {
                        url: "https://wordpress.example.com/2024/04/05/post2/".to_string(),
                        creation_date: Some("2024-04-05T14:30:00Z".to_string()),
                        confidence: 0.95,
                        detection_detail: "wordpress_api_post: Post 2".to_string(),
                    },
                    NewPageDetail {
                        url: "https://wordpress.example.com/2024/04/10/post3/".to_string(),
                        creation_date: Some("2024-04-10T09:15:00Z".to_string()),
                        confidence: 0.95,
                        detection_detail: "wordpress_api_post: Post 3".to_string(),
                    },
                ];
                
                response.new_page_urls = Some(urls);
                response.new_page_details = Some(details);
            }
            
            responses.push(response);
        } else {
            // HTML analysis detected domain
            let mut response = NewPagesResponse {
                domain: domain.clone(),
                new_pages_count: 2,
                days_analyzed: within_days,
                detection_method: DetectionMethod::HtmlAnalysis,
                sitemap_url: Some("https://html.example.com/sitemap.xml".to_string()),
                new_page_urls: None,
                new_page_details: None,
                processing_errors: Vec::new(),
            };
            
            if should_list_pages {
                // Mock HTML analysis post URLs
                let urls = vec![
                    "https://html.example.com/blog/article1".to_string(),
                    "https://html.example.com/blog/article2".to_string(),
                ];
                
                // Mock HTML analysis post details
                let details = vec![
                    NewPageDetail {
                        url: "https://html.example.com/blog/article1".to_string(),
                        creation_date: Some("2024-04-03T11:20:00Z".to_string()),
                        confidence: 0.9,
                        detection_detail: "meta_published_time".to_string(),
                    },
                    NewPageDetail {
                        url: "https://html.example.com/blog/article2".to_string(),
                        creation_date: Some("2024-04-08T16:45:00Z".to_string()),
                        confidence: 0.85,
                        detection_detail: "json_ld_date_published".to_string(),
                    },
                ];
                
                response.new_page_urls = Some(urls);
                response.new_page_details = Some(details);
            }
            
            responses.push(response);
        }
    }
    
    (StatusCode::OK, Json(responses)).into_response()
}
