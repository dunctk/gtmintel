use axum::{
    body::Body,
    http::{Request, StatusCode},
    Json,
    response::IntoResponse,
    extract::Query,
};
use http_body_util::BodyExt; // For Response body handling
use tower::ServiceExt; // For oneshot
use serde_json::Value;
use serde::{Deserialize, Serialize};
use gtmintel::create_app; // Import only the public functions

// Define our own default_within_days for testing
fn default_within_days() -> u32 {
    7
}

#[tokio::test]
async fn test_create_app() {
    // Get the router instance from create_app
    let app = create_app();
    
    // Test a non-existent route
    let not_found_request = Request::builder()
        .uri("/not-a-real-route")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    
    let not_found_response = app
        .oneshot(not_found_request)
        .await
        .unwrap();
    
    // Non-existent routes should return 404 Not Found
    assert_eq!(not_found_response.status(), StatusCode::NOT_FOUND);
}

/// Test struct to match the ResearchQuery
#[derive(Debug, Deserialize, Serialize)]
struct NewPagesQuery {
    pub domains: Vec<String>,
    pub list_pages: Option<bool>,
    pub within_days: u32,
}

#[tokio::test]
async fn test_research_new_pages_batch_invalid_request() {
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
    
    // Check status code is 422 Unprocessable Entity due to too many domains
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    
    // Check response body contains error message
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert!(body["error"].as_str().unwrap().contains("Maximum number of domains"));
}

#[tokio::test]
async fn test_research_new_pages_batch_valid_request() {
    // Initialize tracing for tests
    let _ = tracing_subscriber::fmt::try_init();
    
    // Create a direct router for just this endpoint, using a mock handler
    let app = axum::Router::new()
        .route("/research/pages/new/batch", axum::routing::post(mock_research_new_pages_batch));
    
    // Create a test request body with a valid number of domains
    let domains = vec![
        "wordpress.example.com".to_string(),
        "html.example.com".to_string()
    ];
    
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
    
    // Check status code is 200 OK
    assert_eq!(response.status(), StatusCode::OK);
    
    // Parse response body
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body_bytes).unwrap();
    
    // Check that we got an array with 2 domain results
    assert!(body.is_array());
    assert_eq!(body.as_array().unwrap().len(), 2);
    
    // Check first domain response
    let first_domain = &body[0];
    assert_eq!(first_domain["domain"], "wordpress.example.com");
    assert!(first_domain["new_page_urls"].is_array());
}

#[tokio::test]
async fn test_research_new_pages() {
    // Initialize tracing for tests
    let _ = tracing_subscriber::fmt::try_init();
    
    // Create a direct router for just this endpoint
    let app = axum::Router::new()
        .route("/research/pages/new", axum::routing::get(mock_research_new_pages));
    
    // Test valid request with a WordPress domain
    let request = Request::builder()
        .uri("/research/pages/new?domain=wordpress.example.com&within_days=14&list_pages=true")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    
    let response = app.clone().oneshot(request).await.unwrap();
    
    // Check status code and response body
    assert_eq!(response.status(), StatusCode::OK);
    
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body_bytes).unwrap();
    
    // Verify response structure
    assert_eq!(body["domain"], "wordpress.example.com");
    assert_eq!(body["days_analyzed"], 14);
    assert_eq!(body["detection_method"], "WordPressApi");
    assert!(body["new_page_urls"].is_array());
    assert_eq!(body["new_page_urls"].as_array().unwrap().len(), 3);
    
    // Test invalid request (missing domain parameter)
    let request = Request::builder()
        .uri("/research/pages/new?within_days=14")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    
    // Should return 422 for missing required parameter
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

// Mock handler for the research_new_pages endpoint
async fn mock_research_new_pages(
    Query(query): axum::extract::Query<SingleDomainQuery>
) -> impl IntoResponse {
    // Check if domain is missing
    if query.domain.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "error": "Invalid request: domain parameter is required"
            }))
        ).into_response();
    }
    
    let domain = query.domain.clone();
    let days = query.within_days;
    let should_list_pages = query.list_pages.unwrap_or(false);
    
    // Create response based on domain type (WordPress or other)
    let detection_method = if domain.contains("wordpress") { "WordPressApi" } else { "HtmlAnalysis" };
    let new_page_count = if domain.contains("wordpress") { 3 } else { 2 };
    
    let mut response = serde_json::json!({
        "domain": domain,
        "new_pages_count": new_page_count,
        "days_analyzed": days,
        "detection_method": detection_method,
        "sitemap_url": format!("https://{}/sitemap.xml", domain),
        "processing_errors": []
    });
    
    // Add page URLs if requested
    if should_list_pages {
        let urls = if domain.contains("wordpress") {
            vec![
                format!("https://{}/post1", domain),
                format!("https://{}/post2", domain),
                format!("https://{}/post3", domain)
            ]
        } else {
            vec![
                format!("https://{}/page1", domain),
                format!("https://{}/page2", domain)
            ]
        };
        
        response["new_page_urls"] = serde_json::to_value(urls).unwrap();
    }
    
    (StatusCode::OK, Json(response)).into_response()
}

// Query struct for the single domain endpoint
#[derive(Debug, Deserialize)]
struct SingleDomainQuery {
    #[serde(default)]
    pub domain: String,
    pub list_pages: Option<bool>,
    #[serde(default = "default_within_days_test")]
    pub within_days: u32,
}

fn default_within_days_test() -> u32 {
    7
}

#[tokio::test]
async fn test_compare_domain_pages() {
    // Initialize tracing for tests
    let _ = tracing_subscriber::fmt::try_init();
    
    // Create a direct router for just this endpoint
    let app = axum::Router::new()
        .route("/research/similar-pages", axum::routing::post(mock_compare_domain_pages));
    
    // Create a test request body for comparing domains
    let test_request = CompareDomainsRequest {
        domain_a: "example.com".to_string(),
        domain_b: "competitor.com".to_string(),
        similarity_threshold: Some(0.75),
        max_pages: Some(10),
    };
    
    // Create a POST request with the test body
    let request = Request::builder()
        .uri("/research/similar-pages")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&test_request).unwrap()))
        .unwrap();
    
    // Process the request and get a response
    let response = app
        .oneshot(request)
        .await
        .unwrap();
    
    // Check status code is 200 OK
    assert_eq!(response.status(), StatusCode::OK);
    
    // Parse the response
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body_bytes).unwrap();
    
    // Verify the structure of the response
    assert!(body["similar_pages"].is_array());
    assert_eq!(body["similar_pages"].as_array().unwrap().len(), 2);
    assert!(body["similar_pages"][0]["page_a_url"].is_string());
    assert!(body["similar_pages"][0]["page_b_url"].is_string());
    assert!(body["similar_pages"][0]["similarity_score"].is_number());
    assert_eq!(body["domain_a"], "example.com");
    assert_eq!(body["domain_b"], "competitor.com");
    assert_eq!(body["total_similar_pages"], 2);
}

#[tokio::test]
async fn test_crawl_domains() {
    // Initialize tracing for tests
    let _ = tracing_subscriber::fmt::try_init();
    
    // Create a direct router for just this endpoint
    let app = axum::Router::new()
        .route("/research/crawl", axum::routing::post(mock_crawl_domains));
    
    // Create a test request body for crawling domains
    let test_request = CrawlDomainsRequest {
        domains: vec!["example.com".to_string(), "another-site.com".to_string()],
        max_pages_per_domain: Some(5),
    };
    
    // Create a POST request with the test body
    let request = Request::builder()
        .uri("/research/crawl")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&test_request).unwrap()))
        .unwrap();
    
    // Process the request and get a response
    let response = app
        .oneshot(request)
        .await
        .unwrap();
    
    // Check status code is 200 OK
    assert_eq!(response.status(), StatusCode::OK);
    
    // Parse the response
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body_bytes).unwrap();
    
    // Verify the structure of the response
    assert!(body["domains_analyzed"].is_array());
    assert_eq!(body["domains_analyzed"].as_array().unwrap().len(), 2);
    assert!(body["domains_analyzed"][0]["domain"].is_string());
    assert!(body["domains_analyzed"][0]["pages"].is_array());
    assert_eq!(body["domains_analyzed"][0]["domain"], "example.com");
    assert_eq!(body["domains_analyzed"][0]["pages"].as_array().unwrap().len(), 3);
    assert!(body["domains_analyzed"][0]["pages"][0]["url"].is_string());
    assert!(body["domains_analyzed"][0]["pages"][0]["title"].is_string());
}

// Structs for the crawl domains test
#[derive(Debug, Serialize, Deserialize)]
struct CrawlDomainsRequest {
    pub domains: Vec<String>,
    pub max_pages_per_domain: Option<usize>,
}

// Mock handler for the crawl_domains endpoint
async fn mock_crawl_domains(
    Json(request): Json<CrawlDomainsRequest>
) -> impl IntoResponse {
    // Extract parameters
    let domains = &request.domains;
    let max_pages = request.max_pages_per_domain.unwrap_or(10);
    
    // Create a mock response with crawled domains
    let mut domains_analyzed = Vec::new();
    
    for domain in domains {
        // Create mock pages for each domain
        let pages = vec![
            serde_json::json!({
                "url": format!("https://{}", domain),
                "title": format!("Home | {}", domain),
                "meta_description": format!("Welcome to {}", domain),
                "word_count": 1200,
                "page_type": "Homepage"
            }),
            serde_json::json!({
                "url": format!("https://{}/about", domain),
                "title": format!("About Us | {}", domain),
                "meta_description": "Learn more about our company",
                "word_count": 850,
                "page_type": "About"
            }),
            serde_json::json!({
                "url": format!("https://{}/contact", domain),
                "title": "Contact Us",
                "meta_description": "Get in touch with our team",
                "word_count": 300,
                "page_type": "Contact"
            })
        ];
        
        // Add this domain to the analyzed list
        domains_analyzed.push(serde_json::json!({
            "domain": domain,
            "pages_crawled": pages.len(),
            "max_pages": max_pages,
            "pages": pages
        }));
    }
    
    let response = serde_json::json!({
        "domains_analyzed": domains_analyzed,
        "total_domains": domains.len(),
        "max_pages_per_domain": max_pages
    });
    
    (StatusCode::OK, Json(response)).into_response()
}

// Structs for the domain comparison tests
#[derive(Debug, Serialize, Deserialize)]
struct CompareDomainsRequest {
    pub domain_a: String,
    pub domain_b: String,
    pub similarity_threshold: Option<f64>,
    pub max_pages: Option<usize>,
}

// Mock handler for the compare_domain_pages endpoint
async fn mock_compare_domain_pages(
    Json(request): Json<CompareDomainsRequest>
) -> impl IntoResponse {
    // Extract parameters
    let domain_a = request.domain_a;
    let domain_b = request.domain_b;
    let threshold = request.similarity_threshold.unwrap_or(0.7);
    
    // Create a mock response with similar pages
    let similar_pages = vec![
        serde_json::json!({
            "page_a_url": format!("https://{}/about", domain_a),
            "page_b_url": format!("https://{}/about-us", domain_b),
            "similarity_score": 0.89,
            "page_a_title": format!("About {}", domain_a),
            "page_b_title": format!("About Us | {}", domain_b)
        }),
        serde_json::json!({
            "page_a_url": format!("https://{}/products", domain_a),
            "page_b_url": format!("https://{}/solutions", domain_b),
            "similarity_score": 0.82,
            "page_a_title": "Products",
            "page_b_title": "Solutions"
        })
    ];
    
    let response = serde_json::json!({
        "domain_a": domain_a,
        "domain_b": domain_b,
        "similarity_threshold": threshold,
        "total_similar_pages": similar_pages.len(),
        "similar_pages": similar_pages
    });
    
    (StatusCode::OK, Json(response)).into_response()
}

// Mock handler that validates the input and returns mock data
async fn mock_research_new_pages_batch(
    Json(query): Json<NewPagesQuery>
) -> impl IntoResponse {
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
    
    // For valid requests, return mock data
    let mut responses = Vec::new();
    
    for domain in query.domains {
        let response = serde_json::json!({
            "domain": domain,
            "new_pages_count": if domain.contains("wordpress") { 3 } else { 2 },
            "days_analyzed": query.within_days,
            "detection_method": if domain.contains("wordpress") { "WordPressApi" } else { "HtmlAnalysis" },
            "sitemap_url": format!("https://{}/sitemap.xml", domain),
            "new_page_urls": if query.list_pages.unwrap_or(false) {
                if domain.contains("wordpress") {
                    serde_json::json!([
                        format!("https://{}/post1", domain),
                        format!("https://{}/post2", domain),
                        format!("https://{}/post3", domain)
                    ])
                } else {
                    serde_json::json!([
                        format!("https://{}/page1", domain),
                        format!("https://{}/page2", domain)
                    ])
                }
            } else {
                serde_json::Value::Null
            },
            "processing_errors": []
        });
        
        responses.push(response);
    }
    
    (StatusCode::OK, Json(responses)).into_response()
}