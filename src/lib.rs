use axum::{
    extract::{Query, State},
    routing::{get, post},
    Router,
    Json,
    response::IntoResponse,
    http::StatusCode,
};
// Conditionally import SwaggerUi only when needed (not test)
#[cfg(not(test))]
use utoipa_swagger_ui::SwaggerUi;
use serde::{Deserialize, Serialize};
// Conditionally import CORS only when needed (not test)
#[cfg(not(test))]
use tower_http::cors::{CorsLayer, Any};
use utoipa::{OpenApi, ToSchema, IntoParams};
use std::error::Error;
use sitemap::reader::{SiteMapReader, SiteMapEntity};
use sitemap::structs::LastMod;
use chrono::{Utc, Duration};
use std::io::Cursor;
use texting_robots::Robot;
use std::collections::{VecDeque, HashSet, HashMap};
// Conditionally import Governor only when needed (not test)
#[cfg(not(test))]
use tower_governor::{
    governor::GovernorConfigBuilder,
    key_extractor::SmartIpKeyExtractor,
    GovernorLayer
};
#[cfg(not(test))]
use std::num::NonZeroU32;
// Always import Arc as it's needed in both test and non-test builds
use std::sync::Arc;
use spider::website::Website;
use futures::future::join_all;
use select::document::Document;
use select::predicate::{Name, Attr};
use llm_readability::extractor;
use reqwest::Client;
use url::Url;
// --- Add backoff imports ---
use backoff::future::retry_notify;
use backoff::Error as BackoffError;
use backoff::ExponentialBackoff;
// --- End backoff imports ---
use tracing::Instrument;
use std::time::Instant;
// --- Embed Anything imports ---
use embed_anything::embeddings::embed::{Embedder, EmbedderBuilder};
use once_cell::sync::Lazy;
use html2text;
use embed_anything::embeddings::embed::EmbeddingResult;
use regex;
// --- HTTP Cache Imports ---
use reqwest_middleware::ClientWithMiddleware;
use http_cache_reqwest::{Cache, CacheMode, CACacheManager, HttpCache, HttpCacheOptions};
use reqwest_middleware::ClientBuilder;
// --- End HTTP Cache Imports ---

// --- Global Embedder Initialization ---
// Place this near the top, after imports
static TEXT_EMBEDDER: Lazy<Arc<Embedder>> = Lazy::new(|| {
    let model_architecture = "bert";
    let model_name = "sentence-transformers/all-MiniLM-L6-v2";
    let embedder = EmbedderBuilder::new()
        .model_architecture(model_architecture)
        .model_id(Some(model_name))
        .from_pretrained_hf()
        .expect("Failed to initialize Embedder via builder.");
    Arc::new(embedder)
});
// --- End Global Embedder Initialization ---

// --- Global HTTP Client Initialization ---
static HTTP_CLIENT: Lazy<ClientWithMiddleware> = Lazy::new(|| {
    ClientBuilder::new(Client::new())
        .with(Cache(HttpCache {
            mode: CacheMode::Default, // Use default caching rules
            manager: CACacheManager::default(), // Store cache data in default OS location
            options: HttpCacheOptions::default(), // Use default cache options
        }))
        .build()
});
// --- End Global HTTP Client Initialization ---

// --- Define AppState AFTER TEXT_EMBEDDER and HTTP_CLIENT, but BEFORE functions ---
#[derive(Clone)]
struct AppState {
    embedder: Arc<Embedder>,
    http_client: ClientWithMiddleware, // Add the cached client
}
// --- End AppState Definition ---

#[derive(Debug, Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ResearchQuery {
    /// Domain name to analyze
    domain: String,
    /// Optional: Set to true to include the list of updated page URLs in the response. Defaults to false.
    #[serde(default)]
    #[param(required = false)]
    list_pages: Option<bool>,
    /// Optional: Number of days in the past to check for updated pages. Defaults to 7.
    #[serde(default = "default_within_days")] // Use a function for default
    #[param(required = false)]
    within_days: u32,
}

// Function to provide the default value for within_days
fn default_within_days() -> u32 {
    7
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ResearchResponse {
    /// Domain that was analyzed
    domain: String,
    /// Number of pages updated within the specified period
    updated_pages: i32,
    /// Number of days analyzed (period in the past)
    days_analyzed: u32,
    /// URL of the sitemap that was analyzed (if found)
    sitemap_url: Option<String>,
    /// Optional: List of URLs for pages updated within the specified period (present if list_pages=true)
    #[serde(skip_serializing_if = "Option::is_none")]
    updated_page_urls: Option<Vec<String>>,
}

/// Get the number of pages updated within a specified number of days for a given domain
#[utoipa::path(
    get,
    path = "/research/pages/updated",
    params(ResearchQuery),
    responses(
        (status = 200, description = "Success, sitemap found and processed", body = ResearchResponse),
        (status = 422, description = "Unprocessable Entity - Sitemap not found", body = ResearchResponse)
    )
)]
#[tracing::instrument(skip(query, state), fields(domain = %query.domain))]
async fn research_pages(
    Query(query): Query<ResearchQuery>,
    State(state): State<AppState> // Inject AppState
) -> impl IntoResponse {
    // Pass the client from state to find_sitemap
    let sitemap_result = find_sitemap(&query.domain, state.http_client.clone()).await;

    // Use the provided or default 'within_days' value
    let days_to_analyze = query.within_days;

    // Initialize response body with updated field names and days_analyzed
    let mut response_body = ResearchResponse {
        domain: query.domain.clone(),
        updated_pages: 0,
        days_analyzed: days_to_analyze,
        sitemap_url: None,
        updated_page_urls: None,
    };

    let should_list_pages = query.list_pages.unwrap_or(false);

    match sitemap_result {
        Ok(Some(sitemap_url)) => {
            response_body.sitemap_url = Some(sitemap_url.clone());
            // Pass the client from state to count_recent_pages
            match count_recent_pages(&sitemap_url, days_to_analyze, state.http_client.clone()).await {
                Ok((count, urls)) => {
                    response_body.updated_pages = count;
                    if should_list_pages {
                        response_body.updated_page_urls = Some(urls);
                    }
                    tracing::info!("Found {} pages updated within {} days in sitemap", count, days_to_analyze);
                    (StatusCode::OK, Json(response_body))
                },
                Err(e) => {
                    tracing::error!("Error counting pages from sitemap: {}", e);
                    (StatusCode::OK, Json(response_body))
                }
            }
        },
        Ok(None) => {
            tracing::info!("No sitemap found");
            (StatusCode::UNPROCESSABLE_ENTITY, Json(response_body))
        },
        Err(e) => {
            tracing::error!("Error finding sitemap: {}", e);
            (StatusCode::UNPROCESSABLE_ENTITY, Json(response_body))
        }
    }
}

/// Attempts to find the sitemap URL for a given domain, checking robots.txt first, then common locations.
#[tracing::instrument(skip(domain, client), fields(domain = %domain))]
async fn find_sitemap(
    domain: &str,
    client: ClientWithMiddleware // Accept the cached client
) -> Result<Option<String>, Box<dyn Error + Send + Sync>> {
    // Ensure domain has protocol and no trailing slash
    let base_url = if !domain.starts_with("http") {
        format!("https://{}", domain)
    } else {
        // Remove potential trailing slash for consistent URL building
        domain.trim_end_matches('/').to_string()
    };

    // 1. Try fetching and parsing robots.txt using the cached client
    let robots_url = format!("{}/robots.txt", base_url);
    tracing::info!("Attempting to fetch robots.txt from: {}", robots_url);

    match client.get(&robots_url).send().await {
        Ok(response) => {
            if response.status().is_success() {
                match response.text().await {
                    Ok(content) => {
                        // Use Robot::new with a user-agent and the content bytes
                        match Robot::new("*", content.as_bytes()) {
                            Ok(robot) => {
                                // Check the sitemaps field
                                if let Some(sitemap_url) = robot.sitemaps.first() {
                                    tracing::info!("Found sitemap in robots.txt: {}", sitemap_url);
                                    return Ok(Some(sitemap_url.clone()));
                                } else {
                                    tracing::info!("No sitemaps listed in robots.txt.");
                                }
                            }
                            Err(e) => {
                                // Log parsing error but continue to guessing
                                tracing::warn!("Failed to parse robots.txt ({}): {}", robots_url, e);
                            }
                        }
                    },
                    Err(e) => {
                         // Log text extraction error but continue to guessing
                         tracing::warn!("Failed to read robots.txt content ({}): {}", robots_url, e);
                    }
                }
            } else {
                tracing::info!("robots.txt request failed or not found ({} - Status: {})", robots_url, response.status());
            }
        }
        Err(e) => {
            // Log fetch error but continue to guessing
            tracing::warn!("Error fetching robots.txt ({}): {}", robots_url, e);
        }
    }

    // 2. If robots.txt didn't yield a sitemap, try common locations (fallback)
    tracing::info!("Falling back to guessing common sitemap locations for {}", base_url);
    let sitemap_guesses = vec![
        format!("{}/sitemap.xml", base_url),
        format!("{}/sitemap_index.xml", base_url),
        format!("{}/sitemap/sitemap.xml", base_url), // Kept this common guess
    ];

    for url in sitemap_guesses {
        // Use HEAD request with the cached client
        match client.head(&url).send().await {
            Ok(response) if response.status().is_success() => {
                tracing::info!("Found sitemap by guessing: {}", url);
                return Ok(Some(url)); // Return the guess URL
            }
            Ok(response) => {
                tracing::debug!("Guess failed for {}: Status {}", url, response.status());
            }
            Err(e) => {
                 tracing::debug!("Error checking guess {}: {}", url, e);
            }
        }
    }

    // 3. If neither method worked, return None
    tracing::info!("Could not find sitemap for {} via robots.txt or common locations.", domain);
    Ok(None)
}

/// Count pages modified within the last `days` from a sitemap URL, handling sitemap indexes.
/// Returns a tuple: (count, list_of_updated_page_urls).
#[tracing::instrument(skip(initial_sitemap_url, client), fields(initial_sitemap_url = %initial_sitemap_url, days = %days))]
async fn count_recent_pages(
    initial_sitemap_url: &str,
    days: u32,
    client: ClientWithMiddleware // Accept the cached client
) -> Result<(i32, Vec<String>), Box<dyn Error + Send + Sync>> {
    let mut pages_counted = 0;
    let mut updated_page_urls: Vec<String> = Vec::new();
    // Calculate the cutoff date based on the 'days' parameter
    // Convert days (u32) safely to i64 for Duration::days
    let cutoff_date = Utc::now() - Duration::days(days as i64);

    let mut sitemap_queue: VecDeque<String> = VecDeque::new();
    sitemap_queue.push_back(initial_sitemap_url.to_string());
    let mut processed_sitemaps: HashSet<String> = HashSet::new();

    while let Some(sitemap_url) = sitemap_queue.pop_front() {
        if !processed_sitemaps.insert(sitemap_url.clone()) {
            tracing::debug!("Skipping already processed sitemap: {}", sitemap_url);
            continue;
        }
        tracing::info!("Processing sitemap: {}", sitemap_url);

        // Use the passed client
        let sitemap_response = match client.get(&sitemap_url).send().await {
            Ok(res) => res,
            Err(e) => {
                tracing::error!("Failed to fetch sitemap {}: {}", sitemap_url, e);
                continue;
            }
        };
        if !sitemap_response.status().is_success() {
            tracing::warn!("Failed to fetch sitemap {} - Status: {}", sitemap_url, sitemap_response.status());
            continue;
        }
        let sitemap_content = match sitemap_response.bytes().await {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!("Failed to read bytes from sitemap {}: {}", sitemap_url, e);
                continue;
            }
        };

        let cursor = Cursor::new(sitemap_content);
        let parser = SiteMapReader::new(cursor);

        for entity in parser {
            match entity {
                SiteMapEntity::Url(url_entry) => {
                    match url_entry.lastmod {
                        LastMod::DateTime(last_mod_date) => {
                            let last_mod_utc = last_mod_date.with_timezone(&Utc);
                            // Use the calculated cutoff_date
                            if last_mod_utc >= cutoff_date {
                                pages_counted += 1;
                                if let Some(loc_url) = url_entry.loc.get_url() {
                                    updated_page_urls.push(loc_url.to_string());
                                }
                            }
                        },
                        _ => {}
                    }
                },
                SiteMapEntity::SiteMap(sitemap_entry) => {
                    if let Some(nested_sitemap_url) = sitemap_entry.loc.get_url() {
                        let nested_url_str = nested_sitemap_url.to_string();
                        tracing::debug!("Found nested sitemap, adding to queue: {}", nested_url_str);
                        sitemap_queue.push_back(nested_url_str);
                    } else {
                        tracing::warn!("Sitemap entry location could not be resolved to a URL: {:?}", sitemap_entry.loc);
                    }
                },
                SiteMapEntity::Err(error) => {
                    tracing::warn!("Error parsing entity in {}: {}", sitemap_url, error);
                }
            }
        }
    }

    // Update log message to be generic
    tracing::info!("Finished processing. Found {} pages updated within the last {} days.", pages_counted, days);
    Ok((pages_counted, updated_page_urls))
}

/// Health check endpoint - EXTREMELY Simplified
#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "Service is healthy", body = String)
    )
)]
async fn health_check() -> impl IntoResponse {
    // Return both status code and a string body to match OpenAPI docs
    (StatusCode::OK, "Service is healthy")
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "GTM INTEL API",
        version = "0.0.1",
        license(
            name = "Sustainable Use License",
            url = "https://github.com/dunctk/gtmintel/blob/main/LICENSE.md"
        )
    ),
    paths(
        research_pages,
        health_check,
        crawl_domains,
        compare_domain_pages
    ),
    components(schemas(
        ResearchQuery, 
        ResearchResponse,
        CrawlDomainsRequest,
        CrawlDomainsResponse,
        PageInfo,
        CompareDomainsRequest,
        CompareDomainsResponse,
        SimilarPagePair,
        PageMetadata
    ))
)]
struct ApiDoc;

/// Create the application with all routes and middleware
pub fn create_app() -> Router {
    // Build our API documentation (needed regardless for ApiDoc::openapi())
    let api_doc = ApiDoc::openapi();

    // --- Get the globally initialized embedder ---
    let shared_embedder = TEXT_EMBEDDER.clone();
    // --- Get the globally initialized HTTP client ---
    let shared_http_client = HTTP_CLIENT.clone();

    // Create the application state with both client and embedder
    let app_state = AppState {
        embedder: shared_embedder,
        http_client: shared_http_client, // Add the client to the state
    };

    // --- Define API routes separately ---
    let api_routes = Router::new()
        .route("/research/pages/updated", get(research_pages))
        .route("/health", get(health_check))
        .route("/research/crawl", post(crawl_domains))
        .route("/research/similar-pages", post(compare_domain_pages))
        .with_state(app_state.clone()); // Pass state to API routes
        
    // --- Conditionally apply layers and Swagger UI only when NOT running tests ---
    #[cfg(not(test))]
    let (docs_router, rate_limited_api_routes) = {
        // Create Swagger UI router
        let docs_router = SwaggerUi::new("/docs").url("/api-doc/openapi.json", api_doc);

        // Configure Rate Limiting
        let governor_conf = Arc::new(
            GovernorConfigBuilder::default()
                .key_extractor(SmartIpKeyExtractor)
                .period(std::time::Duration::from_secs(60))
                .burst_size(NonZeroU32::new(10).unwrap().into())
                .finish()
                .unwrap(),
        );
        // Apply Governor layer ONLY to the api_routes defined above
        let rate_limited_api_routes = api_routes.layer(GovernorLayer { config: governor_conf });

        (docs_router, rate_limited_api_routes)
    };

    // For test builds, use the original api_routes and an empty router for docs
    #[cfg(test)]
    let (docs_router, rate_limited_api_routes) = (Router::new(), api_routes);


    // --- Build the final application router ---
    // Start with the rate-limited API routes and merge the docs router
    let mut app = Router::new()
        .merge(rate_limited_api_routes) // Add rate-limited API routes
        .merge(docs_router);            // Add documentation routes (not rate-limited)


    // --- Apply CORS to the whole app (both API and docs) if needed ---
    #[cfg(not(test))]
    {
        app = app.layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        );
    }

    // Return the final router
    app
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CompareDomainsRequest {
    /// First domain to compare
    domain_a: String,
    /// Second domain to compare
    domain_b: String,
    /// Cosine similarity threshold (0.0-1.0) for comparing page embeddings (default: 0.7)
    #[serde(default = "default_similarity_threshold")]
    #[schema(example = 0.75)]
    similarity_threshold: f64,
}

fn default_similarity_threshold() -> f64 {
    0.7
}

#[derive(Debug, Serialize, ToSchema, Clone)]
pub struct PageMetadata {
    /// URL of the page
    url: String,
    /// Title extracted by llm_readability (if available)
    title: Option<String>,
}

// --- Add PageType Enum near other structs/enums ---
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PageType {
    Blog,
    Solution,
    Product,
    CaseStudy,
    Documentation,
    LandingPage, // e.g., specific marketing pages
    About,
    Contact,
    Legal, // Privacy, Terms, etc. (could refine further)
    General, // Generic content page
    Unknown, // Couldn't classify
}

impl Default for PageType {
    fn default() -> Self {
        PageType::Unknown
    }
}
// --- End PageType Enum ---

#[derive(Debug, Clone)]
struct ProcessedPage {
    metadata: PageMetadata,
    embedding: Option<Vec<f32>>,
    h1: Option<String>,
    meta_description: Option<String>,
    intro_text: String,
    page_type: PageType, // <-- Add this field
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SimilarPagePair {
    /// Page from the first domain (domain_a)
    page_a: PageMetadata,
    /// Page from the second domain (domain_b)
    page_b: PageMetadata,
    /// Calculated cosine similarity score
    #[schema(/* Add other valid schema attributes here if needed, e.g., example = 0.88 */)]
    similarity_score: f64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CompareDomainsResponse {
    /// First domain analyzed
    domain_a: String,
    /// Second domain analyzed
    domain_b: String,
    /// List of similar page pairs
    similar_pages: Vec<SimilarPagePair>,
    /// URLs from the first domain's sitemap that failed to process
    domain_a_processing_errors: Vec<String>,
    /// URLs from the second domain's sitemap that failed to process
    domain_b_processing_errors: Vec<String>,
}

// --- Add Page Classifier Function ---
#[tracing::instrument(skip(metadata, h1), fields(url = %metadata.url))]
fn classify_page_type(metadata: &PageMetadata, h1: Option<&str>) -> PageType {
    let url_lower = metadata.url.to_lowercase();
    let title_lower = metadata.title.as_deref().unwrap_or("").to_lowercase();
    let h1_lower = h1.unwrap_or("").to_lowercase();

    // --- URL Path Analysis ---
    if let Ok(parsed_url) = Url::parse(&metadata.url) {
        if let Some(mut path_segments) = parsed_url.path_segments() {
            // Check first few path segments for strong indicators
            if let Some(first_segment) = path_segments.next() {
                match first_segment {
                    "blog" | "posts" | "news" | "insights" | "articles" => return PageType::Blog,
                    "solutions" | "services" | "platform" | "features" => return PageType::Solution,
                    "products" | "store" | "shop" => return PageType::Product,
                    "case-studies" | "casestudies" | "customer-stories" | "success-stories" => return PageType::CaseStudy,
                    "docs" | "documentation" | "guides" | "api" | "help" | "support" => return PageType::Documentation,
                    "legal" | "privacy" | "terms" | "imprint" | "impressum" | "cookies" => return PageType::Legal,
                    "about" | "company" | "team" => return PageType::About,
                    "contact" | "support" => return PageType::Contact, // 'support' could be ambiguous
                    _ => {} // Continue checking other segments or heuristics
                }
                 // Check second segment if first wasn't decisive (e.g., /company/blog/...)
                 if let Some(second_segment) = path_segments.next() {
                     match second_segment {
                         "blog" | "posts" | "news" | "insights" | "articles" => return PageType::Blog,
                         "solutions" | "services" => return PageType::Solution,
                         "products" => return PageType::Product,
                         "case-studies" | "casestudies" => return PageType::CaseStudy,
                         "docs" | "documentation" | "guides" => return PageType::Documentation,
                          _ => {}
                     }
                 }
            }
        }
    } else {
        tracing::warn!("Failed to parse URL for classification: {}", metadata.url);
    }

    // --- Title/H1 Keyword Analysis (if URL wasn't decisive) ---
    // Prioritize H1 if available, then title
    let combined_header = format!("{} {}", h1_lower, title_lower);

    if combined_header.contains("blog") || combined_header.contains("post") || combined_header.contains("article") || combined_header.contains("news") {
        return PageType::Blog;
    }
    if combined_header.contains("solution") || combined_header.contains("service") || combined_header.contains("platform") {
        // Be careful not to misclassify blog posts *about* solutions
        if !url_lower.contains("/blog/") && !url_lower.contains("/post/") { // Basic check
             return PageType::Solution;
        }
    }
    if combined_header.contains("product") {
        // Similar check for blog posts about products
        if !url_lower.contains("/blog/") && !url_lower.contains("/post/") {
             return PageType::Product;
        }
    }
    if combined_header.contains("case study") || combined_header.contains("customer story") {
         return PageType::CaseStudy;
    }
     if combined_header.contains("documentation") || combined_header.contains("guide") || combined_header.contains("api reference") {
         return PageType::Documentation;
    }
     if combined_header.contains("privacy") || combined_header.contains("terms") || combined_header.contains("legal") || combined_header.contains("cookie policy") {
         return PageType::Legal;
    }
     if combined_header.contains("about us") || combined_header.contains("company") || combined_header.contains("our team") {
         return PageType::About;
    }
      if combined_header.contains("contact us") || combined_header.contains("get in touch") {
         return PageType::Contact;
    }

    // --- Simple Landing Page Check (heuristic) ---
    // Check if URL path is empty or just "/"
    if let Ok(parsed_url) = Url::parse(&metadata.url) {
         if parsed_url.path() == "/" || parsed_url.path().is_empty() {
             // Could also check for common landing page titles like "Home"
             if title_lower.contains("home") || title_lower.is_empty() { // Empty title might be homepage
                 return PageType::LandingPage; // Likely Homepage
             }
         }
         // Check for very short paths, potentially marketing pages
         // Note: This rule was commented out in the original example, keeping it commented.
         // You might enable and refine it if needed.
         /*
         if parsed_url.path_segments().map_or(0, |s| s.count()) == 1 {
              // Example: /features, /pricing - needs more refinement maybe
             if !matches!(classify_page_type(metadata, h1), PageType::Unknown | PageType::General) {
                  // If already classified by keywords/URL, respect that
             } else {
                 // Could be a landing page if not otherwise classified
                 // return PageType::LandingPage; // Be cautious with this rule
             }
         }
         */
    }


    // --- Fallback ---
    tracing::debug!("Could not classify page, falling back to General: {}", metadata.url);
    PageType::General // Or Unknown if you prefer a stricter default
}
// --- End Page Classifier Function ---

// --- Add back the retry notification handler ---
fn retry_notify_handler<E>(err: E, duration: std::time::Duration)
where
    E: std::fmt::Display,
{
    tracing::warn!(
        "Request failed: {}. Retrying in {:.1}s...",
        err,
        duration.as_secs_f32()
    );
}
// --- End retry notification handler ---

// --- Add back the cosine similarity helper ---
fn cosine_similarity(vec_a: &[f32], vec_b: &[f32]) -> Option<f64> {
    if vec_a.len() != vec_b.len() || vec_a.is_empty() {
        return None; // Vectors must have same non-zero dimension
    }

    let dot_product = vec_a.iter().zip(vec_b.iter()).map(|(a, b)| a * b).sum::<f32>();
    let norm_a = vec_a.iter().map(|a| a.powi(2)).sum::<f32>().sqrt();
    let norm_b = vec_b.iter().map(|b| b.powi(2)).sum::<f32>().sqrt();

    if norm_a == 0.0 || norm_b == 0.0 {
        return Some(0.0); // Avoid division by zero; zero vectors have 0 similarity
    }

    // Ensure the result is clamped between -1.0 and 1.0 due to potential float inaccuracies
    let similarity = (dot_product / (norm_a * norm_b)) as f64;
    Some(similarity.clamp(-1.0, 1.0))
}
// --- End cosine similarity helper ---

// --- Add back the boilerplate page identifier ---
fn is_boilerplate_page(page: &ProcessedPage) -> bool {
    let url_lower = page.metadata.url.to_lowercase();
    let title_lower = page.metadata.title.as_deref().unwrap_or("").to_lowercase();

    // Keywords to check for in URL path or title
    let boilerplate_keywords = [
        "privacy", "policy", "legal", "terms", "condition",
        "cookie", "disclaimer", "copyright", "accessibility",
        "imprint", "impressum", // Common in some regions
        "about-us", "contact", // Sometimes less relevant for semantic comparison
        // Add more keywords as needed
    ];

    // Check URL path segments
    if let Ok(parsed_url) = Url::parse(&page.metadata.url) {
        if let Some(path_segments) = parsed_url.path_segments() {
            for segment in path_segments {
                let segment_lower = segment.to_lowercase();
                if boilerplate_keywords.iter().any(|&kw| segment_lower.contains(kw)) {
                    tracing::debug!("Identified boilerplate by URL segment: {}", page.metadata.url);
                    return true;
                }
            }
        }
    }

    // Check title
    if boilerplate_keywords.iter().any(|&kw| title_lower.contains(kw)) {
        tracing::debug!("Identified boilerplate by title: '{}' in {}", title_lower, page.metadata.url);
        return true;
    }

    false // Not identified as boilerplate
}
// --- End boilerplate page identifier ---

// --- Add back the sitemap URL extractor ---
#[tracing::instrument(skip(initial_sitemap_url, client), fields(initial_sitemap_url = %initial_sitemap_url))]
async fn get_all_sitemap_urls(
    initial_sitemap_url: &str,
    client: ClientWithMiddleware // Accept the cached client
) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
    let mut all_page_urls: Vec<String> = Vec::new();
    let mut sitemap_queue: VecDeque<String> = VecDeque::new();
    sitemap_queue.push_back(initial_sitemap_url.to_string());
    let mut processed_sitemaps: HashSet<String> = HashSet::new();

    while let Some(sitemap_url) = sitemap_queue.pop_front() {
        if !processed_sitemaps.insert(sitemap_url.clone()) {
            tracing::debug!("Skipping already processed sitemap: {}", sitemap_url);
            continue;
        }
        tracing::info!("Processing sitemap: {}", sitemap_url);

        // Use the passed client
        let sitemap_response = match client.get(&sitemap_url).send().await {
            Ok(res) => res,
            Err(e) => {
                tracing::error!("Failed to fetch sitemap {}: {}", sitemap_url, e);
                // Return error to caller instead of continuing silently
                return Err(format!("Failed to fetch sitemap {}: {}", sitemap_url, e).into());
            }
        };

        if !sitemap_response.status().is_success() {
            tracing::warn!("Failed to fetch sitemap {} - Status: {}", sitemap_url, sitemap_response.status());
            // Return error to caller
             return Err(format!("Failed to fetch sitemap {} - Status: {}", sitemap_url, sitemap_response.status()).into());
        }

        let sitemap_content = match sitemap_response.bytes().await {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!("Failed to read bytes from sitemap {}: {}", sitemap_url, e);
                // Return error to caller
                 return Err(format!("Failed to read bytes from sitemap {}: {}", sitemap_url, e).into());
            }
        };

        let cursor = Cursor::new(sitemap_content);
        let parser = SiteMapReader::new(cursor);

        for entity in parser {
            match entity {
                SiteMapEntity::Url(url_entry) => {
                    if let Some(loc_url) = url_entry.loc.get_url() {
                        all_page_urls.push(loc_url.to_string());
                    } else {
                         tracing::warn!("URL entry location could not be resolved: {:?}", url_entry.loc);
                    }
                },
                SiteMapEntity::SiteMap(sitemap_entry) => {
                    if let Some(nested_sitemap_url) = sitemap_entry.loc.get_url() {
                        let nested_url_str = nested_sitemap_url.to_string();
                        if !processed_sitemaps.contains(&nested_url_str) {
                             tracing::debug!("Found nested sitemap, adding to queue: {}", nested_url_str);
                            sitemap_queue.push_back(nested_url_str);
                        }
                    } else {
                        tracing::warn!("Sitemap entry location could not be resolved to a URL: {:?}", sitemap_entry.loc);
                    }
                },
                SiteMapEntity::Err(error) => {
                    tracing::warn!("Error parsing entity in {}: {}", sitemap_url, error);
                    // Optionally return an error here if strict parsing is required
                    // return Err(format!("Error parsing entity in {}: {}", sitemap_url, error).into());
                }
            }
        }
    }

    tracing::info!("Found {} total page URLs in sitemap(s) starting from {}", all_page_urls.len(), initial_sitemap_url);
    Ok(all_page_urls)
}
// --- End sitemap URL extractor ---

#[tracing::instrument(skip(url, client, embedder), fields(url = %url))]
async fn fetch_and_process_page(
    url: String,
    client: ClientWithMiddleware, // Accept the cached client
    embedder: Arc<Embedder>
) -> Result<ProcessedPage, Box<dyn Error + Send + Sync>> {
    tracing::debug!("Fetching: {}", url);

    let backoff = ExponentialBackoff::default();

    // Timing the whole function includes retries and processing
    let response = retry_notify(
        backoff,
        || async {
            match client.get(&url).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        Ok(resp) // Success!
                    } else {
                        // Handle status code errors explicitly here
                        let error_string = format!("Server returned status: {}", status);
                        if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
                            tracing::debug!("Retrying on status: {}", status);
                            Err(BackoffError::transient(error_string)) // Pass String
                        } else {
                            // Treat other non-success status codes (like 404, 403, 401) as permanent
                            tracing::debug!("Permanent error status: {}", status);
                            Err(BackoffError::permanent(error_string)) // Pass String
                        }
                    }
                }
                Err(err) => { // err is reqwest_middleware::Error
                    // --- Simplified Error Handling ---
                    // We cannot reliably inspect `err`'s source/type inside here
                    // due to lifetime constraints ('static requirement).
                    // Assume most errors reaching this point (network, timeout, DNS, etc.)
                    // are potentially transient. Status code errors were handled above.
                    let error_string = err.to_string();
                    tracing::debug!("Retrying on middleware/network error: {}", error_string);
                    // Default to transient for errors caught here
                    Err(BackoffError::transient(error_string)) // Pass String
                }
            }
        },
        retry_notify_handler, // <--- Ensure this call site exists and is correct
    )
    // The error type from retry_notify is String
    .await
    // Convert the final String error (if retries failed) into a Box<dyn Error>
    .map_err(|e: String| -> Box<dyn Error + Send + Sync> {
        // Create a standard error from the string message
        Box::new(std::io::Error::new(std::io::ErrorKind::Other, e))
    })?;

    // --- Original Processing Logic (after successful fetch) ---
    let processing_span = tracing::info_span!("blocking_extraction"); // Span for blocking extraction only
    // Handle potential error from response.text() which returns reqwest::Error
    let html_content = response.text().await.map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
    let original_url_string = url.clone();

    // Clone necessary data for the blocking task
    let url_for_blocking = original_url_string.clone();

    // --- Step 1-3 (Inside spawn_blocking): Extract text parts ---
    let extracted_data = tokio::task::spawn_blocking(move || {
        let _enter = processing_span.enter(); // Enter span for blocking work

        // --- Extract Key Fields using select ---
        let document = Document::from(html_content.as_str());
        let title = document.find(Name("title")).next().map(|n| n.text().trim().to_string());
        let h1 = document.find(Name("h1")).next().map(|n| n.text().trim().to_string());
        let meta_description = document
            .find(Attr("name", "description"))
            .next()
            .and_then(|n| n.attr("content"))
            .map(|s| s.trim().to_string());

        // --- Extract Intro Text ---
        // Ensure URL parsing errors are boxed correctly
        let parsed_url_for_extract = Url::parse(&url_for_blocking)
            .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        let intro_text = match extractor::extract(&mut html_content.as_bytes(), &parsed_url_for_extract) {
            Ok(product) => {
                let plain_text_result = html2text::from_read(product.content.as_bytes(), 120);
                plain_text_result.unwrap_or_default()
            }
            Err(e) => {
                tracing::warn!("llm_readability failed for {}: {}", url_for_blocking, e);
                String::new()
            }
        };
        // Increase the word limit from 200 to 500
        let intro_text_cleaned = intro_text.split_whitespace().take(500).collect::<Vec<&str>>().join(" ");


        // --- Construct Representative Text ---
        let representative_text_raw = format!(
            "{} {} {} {}",
            title.as_deref().unwrap_or(""),
            h1.as_deref().unwrap_or(""),
            meta_description.as_deref().unwrap_or(""),
            intro_text_cleaned // Use the cleaned intro text
        ).trim().to_string();

        // --- Extract domain for cleaning ---
        // Ensure domain extraction errors are boxed correctly
        let domain_for_cleaning = parsed_url_for_extract.domain()
            .ok_or_else(|| Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Could not parse domain")) as Box<dyn Error + Send + Sync>)?
            .to_string();

        // --- Clean the representative text ---
        let representative_text = clean_content(&representative_text_raw, &domain_for_cleaning);


        tracing::debug!(url = %url_for_blocking, text_len = representative_text.len(), "Generated representative text");

        // Return extracted components
        Ok::<_, Box<dyn Error + Send + Sync>>((
            representative_text,
            title,
            h1,
            meta_description,
            intro_text_cleaned, // Return the cleaned intro text
        ))
    }).await // This propagates JoinError if the task panics
       .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)? // Map JoinError -> Box<dyn Error>
       ?; // This propagates the inner Result (Ok or Box<dyn Error>) from the closure

    let (representative_text_str, page_title, page_h1, page_meta_desc, page_intro) = extracted_data;

    // --- Step 4 (Outside spawn_blocking): Generate Embedding ---
    let embedding_option: Option<Vec<f32>> = if !representative_text_str.is_empty() {
        let text_to_embed: [&str; 1] = [&representative_text_str]; // Use the cleaned text
        let embedding_span = tracing::info_span!("async_embedding", url = %original_url_string);

        match embedder.embed(&text_to_embed, None, None).instrument(embedding_span).await {
            Ok(mut results) => {
                if let Some(result) = results.pop() {
                    // No need for explicit type annotation anymore
                    // let result: embed_anything::embeddings::embed::EmbeddingResult = result;

                    // Match on the CORRECT EmbeddingResult enum variants
                    match result {
                        // Handle the DenseVector case
                        EmbeddingResult::DenseVector(vector) => {
                            if !vector.is_empty() {
                                Some(vector) // Use the dense vector directly
                            } else {
                                tracing::warn!("Embedding resulted in an empty DenseVector for: {}", original_url_string);
                                None
                            }
                        },
                        // Handle the MultiVector case (e.g., take the first vector or log warning)
                        EmbeddingResult::MultiVector(mut vectors) => {
                            if let Some(first_vector) = vectors.pop() {
                                if !first_vector.is_empty() {
                                    tracing::warn!("Embedding resulted in MultiVector for single input, using first vector for: {}", original_url_string);
                                    Some(first_vector)
                                } else {
                                    tracing::warn!("Embedding resulted in MultiVector with empty first vector for: {}", original_url_string);
                                    None
                                }
                            } else {
                                tracing::warn!("Embedding resulted in an empty MultiVector for: {}", original_url_string);
                                None
                            }
                        }
                        // Removed the Success/Failure arms as they don't exist
                    }
                } else {
                    tracing::warn!("Embedding returned empty result list for: {}", original_url_string);
                    None
                }
            },
            Err(e) => {
                tracing::error!("Embedding generation batch failed for {}: {}", original_url_string, e);
                None // Propagate embedding failure as None, not an error for the whole function
            }
        }
    } else {
        tracing::warn!("No representative text to embed for: {}", original_url_string);
        None
    };


    // --- Create Metadata struct for classifier ---
    let page_metadata = PageMetadata {
        url: original_url_string.clone(), // Use the original URL stored earlier
        title: page_title.clone(),       // Clone title
    };

    // --- Step 5: Classify Page Type ---
    let page_type = classify_page_type(&page_metadata, page_h1.as_deref()); // Pass metadata and H1


    // --- Step 6: Create ProcessedPage ---
    Ok(ProcessedPage {
        metadata: page_metadata, // Use the metadata struct created above
        embedding: embedding_option,
        h1: page_h1, // Store h1
        meta_description: page_meta_desc,
        intro_text: page_intro,
        page_type, // Store the classified page type
    })
}

#[utoipa::path(
    post,
    path = "/research/similar-pages",
    request_body = CompareDomainsRequest,
    responses(
        (status = 200, description = "Comparison complete, returns pairs of pages with similar semantic content", body = CompareDomainsResponse),
        (status = 422, description = "Unprocessable Entity - Error finding/processing sitemaps or invalid request"),
        (status = 500, description = "Internal Server Error during processing or embedding model failure"),
    ),
    description = "Compares pages between two domains based on semantic content similarity using embeddings. Provide domains and a cosine similarity threshold."
)]
#[tracing::instrument(skip(request, state), fields(domain_a = %request.domain_a, domain_b = %request.domain_b))]
async fn compare_domain_pages(
    State(state): State<AppState>,
    Json(request): Json<CompareDomainsRequest>
) -> impl IntoResponse {
    // ---> Record start time <---
    let start_time = Instant::now();

    // ---> ADD VALIDATION FOR THRESHOLD <---
    if !(0.0..=1.0).contains(&request.similarity_threshold) {
         return (StatusCode::UNPROCESSABLE_ENTITY, Json(serde_json::json!({
             "error": "similarity_threshold must be between 0.0 and 1.0"
         }))).into_response();
    }
    // --------------------------------------

    tracing::info!("Starting semantic page comparison for {} vs {} with threshold {}",
        request.domain_a, request.domain_b, request.similarity_threshold);

    let embedder = state.embedder; // Get the embedder Arc from state
    let client = state.http_client; // Get the HTTP client Arc from state

    // --- Get Sitemap URLs (pass client) ---
    let sitemap_url_a = match find_sitemap(&request.domain_a, client.clone()).await {
        Ok(Some(url)) => url,
        Ok(None) => {
            tracing::error!("Sitemap not found for domain_a: {}", request.domain_a);
            // Return CompareDomainsResponse structure on error
            return (StatusCode::UNPROCESSABLE_ENTITY, Json(CompareDomainsResponse {
                domain_a: request.domain_a, domain_b: request.domain_b,
                similar_pages: vec![],
                domain_a_processing_errors: vec!["Sitemap not found".to_string()], // Indicate error source
                domain_b_processing_errors: vec![],
            })).into_response();
        },
        Err(e) => {
            tracing::error!("Error finding sitemap for domain_a {}: {}", request.domain_a, e);
            // Return simple JSON string for internal server errors to avoid complex struct creation on critical failure
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": format!("Error finding sitemap for domain_a: {}", e)}))).into_response();
        }
    };
    let sitemap_url_b = match find_sitemap(&request.domain_b, client.clone()).await {
         Ok(Some(url)) => url,
        Ok(None) => {
            tracing::error!("Sitemap not found for domain_b: {}", request.domain_b);
             return (StatusCode::UNPROCESSABLE_ENTITY, Json(CompareDomainsResponse {
                domain_a: request.domain_a, domain_b: request.domain_b,
                similar_pages: vec![],
                domain_a_processing_errors: vec![],
                domain_b_processing_errors: vec!["Sitemap not found".to_string()], // Indicate error source
            })).into_response();
        },
        Err(e) => {
            tracing::error!("Error finding sitemap for domain_b {}: {}", request.domain_b, e);
             // Return simple JSON string for internal server errors
             return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": format!("Error finding sitemap for domain_b: {}", e)}))).into_response();
        }
    };

    // --- Get All URLs from Sitemaps (pass client) ---
    let urls_a = match get_all_sitemap_urls(&sitemap_url_a, client.clone()).await {
        Ok(urls) => urls,
        Err(e) => {
            tracing::error!("Error getting URLs for domain_a {}: {}", request.domain_a, e);
            // Return simple JSON string for unprocessable entity errors related to sitemap processing
            return (StatusCode::UNPROCESSABLE_ENTITY, Json(serde_json::json!({ "error": format!("Error processing sitemap for domain_a: {}", e)}))).into_response();
        }
    };
     let urls_b = match get_all_sitemap_urls(&sitemap_url_b, client.clone()).await {
        Ok(urls) => urls,
         Err(e) => {
            tracing::error!("Error getting URLs for domain_b {}: {}", request.domain_b, e);
            // Return simple JSON string for unprocessable entity errors related to sitemap processing
            return (StatusCode::UNPROCESSABLE_ENTITY, Json(serde_json::json!({ "error": format!("Error processing sitemap for domain_b: {}", e)}))).into_response();
        }
    };

     if urls_a.is_empty() || urls_b.is_empty() {
         tracing::warn!("One or both domains have zero URLs in sitemap. A: {}, B: {}", urls_a.len(), urls_b.len());
         return (StatusCode::OK, Json(CompareDomainsResponse {
                domain_a: request.domain_a, domain_b: request.domain_b,
                similar_pages: vec![],
                domain_a_processing_errors: vec![],
                domain_b_processing_errors: vec![],
            })).into_response();
     }

    // --- Fetch and Process Pages Concurrently (Pass embedder and client) ---
    let fetch_process_span_a = tracing::info_span!("fetch_process_embed_pages", domain = %request.domain_a);
    let embedder_a = embedder.clone();
    let client_a = client.clone(); // Clone client for domain A tasks
    let futures_a = urls_a.into_iter().map(|url| {
        let client_c = client_a.clone(); // Clone client for this specific task
        let embedder_c = embedder_a.clone();
        // Clone url *before* the closure moves the original url
        let url_for_span = url.clone();
        tokio::spawn(async move {
            // Pass the cloned client `client_c`
            (url.clone(), fetch_and_process_page(url, client_c, embedder_c).await)
        })
        .instrument(tracing::info_span!("process_page_task", url = %url_for_span))
    });
    let results_a = join_all(futures_a).instrument(fetch_process_span_a).await;


    let fetch_process_span_b = tracing::info_span!("fetch_process_embed_pages", domain = %request.domain_b);
    let embedder_b = embedder.clone();
    let client_b = client.clone(); // Clone client for domain B tasks
    let futures_b = urls_b.into_iter().map(|url| {
        let client_c = client_b.clone(); // Clone client for this specific task
        let embedder_c = embedder_b.clone();
        // Clone url *before* the closure moves the original url
        let url_for_span = url.clone();
        tokio::spawn(async move {
            // Pass the cloned client `client_c`
             (url.clone(), fetch_and_process_page(url, client_c, embedder_c).await)
        })
        .instrument(tracing::info_span!("process_page_task", url = %url_for_span))
    });
    let results_b = join_all(futures_b).instrument(fetch_process_span_b).await;


    // --- Separate successful results from errors ---
    let mut processed_a_all: Vec<ProcessedPage> = Vec::new(); // Rename temporarily
    let mut errors_a: Vec<String> = Vec::new();
    for result in results_a {
        match result {
             // Handle JoinError first
             Err(join_error) => tracing::error!("JoinError processing domain_a pages: {}", join_error),
             // Handle Result from fetch_and_process_page
            Ok((_url, Ok(page))) => processed_a_all.push(page), // Use _url
            Ok((url, Err(e))) => {
                tracing::warn!("Failed to process URL for domain_a {}: {}", url, e);
                errors_a.push(url);
            }
        }
    }
    // ... similar separation logic for results_b ...
    let mut processed_b_all: Vec<ProcessedPage> = Vec::new(); // Rename temporarily
    let mut errors_b: Vec<String> = Vec::new();
     for result in results_b {
        match result {
             Err(join_error) => tracing::error!("JoinError processing domain_b pages: {}", join_error),
            Ok((_url, Ok(page))) => processed_b_all.push(page), // Use _url
            Ok((url, Err(e))) => {
                tracing::warn!("Failed to process URL for domain_b {}: {}", url, e);
                errors_b.push(url);
            }
         }
    }

    let initial_count_a = processed_a_all.len(); // Use renamed var
    let initial_count_b = processed_b_all.len(); // Use renamed var

    // --- Filter out boilerplate pages BEFORE type grouping ---
    processed_a_all.retain(|page| !is_boilerplate_page(page));
    processed_b_all.retain(|page| !is_boilerplate_page(page));

    let filtered_count_a = processed_a_all.len(); // Use renamed var
    let filtered_count_b = processed_b_all.len(); // Use renamed var

    tracing::info!(
        "Processed {} pages for domain A ({} errors, {} filtered as boilerplate)",
        initial_count_a, errors_a.len(), initial_count_a - filtered_count_a
    );
    tracing::info!(
         "Processed {} pages for domain B ({} errors, {} filtered as boilerplate)",
        initial_count_b, errors_b.len(), initial_count_b - filtered_count_b
    );
    // --- End filtering ---


    // --- Group Pages by Type ---
    let group_span = tracing::info_span!("group_pages_by_type");
    let _enter_group = group_span.enter();

    let mut pages_by_type_a: HashMap<PageType, Vec<ProcessedPage>> = HashMap::new();
    for page in processed_a_all { // Use the filtered list
        pages_by_type_a.entry(page.page_type.clone()).or_default().push(page);
    }

    let mut pages_by_type_b: HashMap<PageType, Vec<ProcessedPage>> = HashMap::new();
    for page in processed_b_all { // Use the filtered list
        pages_by_type_b.entry(page.page_type.clone()).or_default().push(page);
    }

    // Log counts per type (optional but helpful)
    for (page_type, pages) in &pages_by_type_a {
        tracing::debug!("Domain A: Found {} pages of type {:?}", pages.len(), page_type);
    }
     for (page_type, pages) in &pages_by_type_b {
        tracing::debug!("Domain B: Found {} pages of type {:?}", pages.len(), page_type);
    }

    drop(_enter_group); // End timing for grouping


    // --- Compare Processed Pages within Each Type ---
    let mut similar_pairs: Vec<SimilarPagePair> = Vec::new();
    let comparison_span = tracing::info_span!("compare_embeddings_by_type");
    {
        let _enter = comparison_span.enter();
        let semantic_threshold = request.similarity_threshold;

        // Iterate through types present in domain A
        for (page_type, pages_a) in &pages_by_type_a {
            // Check if this type also exists in domain B
            if let Some(pages_b) = pages_by_type_b.get(page_type) {
                tracing::info!("Comparing pages of type {:?} (A: {}, B: {}) between domains...", page_type, pages_a.len(), pages_b.len());

                // Compare pages *within this specific type*
                for page_a in pages_a {
            if let Some(embed_a) = &page_a.embedding {
            let mut best_match_for_a: Option<&ProcessedPage> = None;
                        let mut highest_similarity_for_a = -2.0;

                        for page_b in pages_b {
                    if let Some(embed_b) = &page_b.embedding {
                        if let Some(similarity) = cosine_similarity(embed_a, embed_b) {
                if similarity > highest_similarity_for_a {
                    highest_similarity_for_a = similarity;
                    best_match_for_a = Some(page_b);
                            }
                        } else {
                             tracing::warn!("Could not calculate similarity between {} and {}", page_a.metadata.url, page_b.metadata.url);
                        }
                }
                        } // End inner loop (pages_b)

                if highest_similarity_for_a >= semantic_threshold {
                if let Some(matched_b) = best_match_for_a {
                        similar_pairs.push(SimilarPagePair {
                        page_a: page_a.metadata.clone(),
                            page_b: matched_b.metadata.clone(),
                                    similarity_score: highest_similarity_for_a,
                    });
                }
            }
            } else {
                        tracing::debug!("Skipping comparison for page_a (type {:?}) without embedding: {}", page_type, page_a.metadata.url);
                    }
                } // End outer loop (pages_a)
            } else { // <--- Else corresponding to `if let Some(pages_b)`
                 tracing::debug!("Skipping type {:?} - not found in domain B", page_type);
            } // <--- End of `if let Some(pages_b)` block
        } // End type loop (pages_by_type_a)
    } // <--- End of comparison scope, correctly closes the block started above

    tracing::info!("Found {} similar page pairs across matched types above threshold {}", similar_pairs.len(), request.similarity_threshold);

    // ---> Calculate and Log Performance Metrics <---
    let total_duration = start_time.elapsed();
    // Use filtered counts for per-page timing
    let total_processed_count = filtered_count_a + filtered_count_b; // Use filtered counts
    let avg_time_per_page = if total_processed_count > 0 { // Use processed count
        total_duration.as_secs_f64() / total_processed_count as f64
    } else {
        0.0
    };

    tracing::info!(
        total_duration_ms = total_duration.as_millis(),
        total_pages_processed_a = filtered_count_a, // Renamed for clarity
        total_pages_processed_b = filtered_count_b, // Renamed for clarity
        avg_time_per_page_ms = avg_time_per_page * 1000.0,
        "Type-specific similarity comparison complete." // Updated log message
    );
    // -------------------------------------------------

    // --- Return Response ---
    (StatusCode::OK, Json(CompareDomainsResponse {
        domain_a: request.domain_a,
        domain_b: request.domain_b,
        similar_pages: similar_pairs,
        domain_a_processing_errors: errors_a,
        domain_b_processing_errors: errors_b,
    })).into_response()
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CrawlDomainsRequest {
    /// List of domains to crawl
    domains: Vec<String>,
    /// Maximum number of pages to crawl per domain (default: 10)
    #[serde(default = "default_max_pages")]
    max_pages: usize,
}

fn default_max_pages() -> usize {
    10
}

#[derive(Debug, Serialize, ToSchema, Clone)]
pub struct PageInfo {
    /// URL of the crawled page
    url: String,
    /// Title of the page (if available)
    title: Option<String>,
    /// Meta description of the page (if available)
    description: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CrawlDomainsResponse {
    /// Domain that was crawled
    domain: String,
    /// List of pages found with their details
    pages: Vec<PageInfo>,
}

/// Crawl multiple domains and extract page information (URLs, titles, meta descriptions)
#[utoipa::path(
    post,
    path = "/research/crawl",
    request_body = CrawlDomainsRequest,
    responses(
        (status = 200, description = "Successfully crawled domains", body = Vec<CrawlDomainsResponse>),
        (status = 422, description = "Invalid request parameters")
    )
)]
#[tracing::instrument(skip(request, state))]
async fn crawl_domains(
    State(state): State<AppState>, // Inject AppState
    Json(request): Json<CrawlDomainsRequest>
) -> impl IntoResponse {
    if request.domains.is_empty() {
        return (StatusCode::UNPROCESSABLE_ENTITY, Json(Vec::<CrawlDomainsResponse>::new())).into_response();
    }

    let client = state.http_client; // Get client from state

    let crawl_futures = request.domains.iter().map(|domain| {
        // Pass the client to crawl_single_domain
        crawl_single_domain(domain, request.max_pages, client.clone())
    });
    
    let crawl_span = tracing::info_span!("crawl_all_requested_domains");
    let results = join_all(crawl_futures).instrument(crawl_span).await;
    
    (StatusCode::OK, Json(results)).into_response()
}

#[tracing::instrument(skip(domain, client), fields(domain = %domain, max_pages = %max_pages))]
async fn crawl_single_domain(
    domain: &str,
    max_pages: usize,
    client: ClientWithMiddleware // Accept client
) -> CrawlDomainsResponse {
    let domain_with_protocol = if domain.starts_with("http") {
        domain.to_string()
    } else {
        format!("https://{}", domain)
    };
    
    let mut website = Website::new(&domain_with_protocol);
    
    website.with_respect_robots_txt(true)
           .with_delay(100)
           .with_request_timeout(Some(std::time::Duration::from_secs(10)))
           .with_limit(max_pages as u32);
    
    let scrape_span = tracing::info_span!("spider_scrape");
    website.scrape().instrument(scrape_span).await;
    
    // Declare pages_info *before* the span scope
    let mut pages_info = Vec::new();
    let process_results_span = tracing::info_span!("process_scraped_pages");
    {
        let _enter = process_results_span.enter(); // Time the sync processing loop
        // Remove the declaration from inside the scope
        if let Some(pages) = website.get_pages() {
            for page in pages.iter() {
                let url = page.get_url().to_string();
                
                let html_content = page.get_html();
                
                let (title, description) = if !html_content.is_empty() {
                    match Document::from_read(html_content.as_bytes()) {
                        Ok(document) => {
                            let title = document.find(Name("title"))
                                .next()
                                .map(|n| n.text().trim().to_string());
                            
                            let description = document.find(Attr("name", "description"))
                                .next()
                                .and_then(|n| n.attr("content"))
                                .map(|s| s.trim().to_string());
                            
                            (title, description)
                        },
                        Err(e) => {
                            tracing::warn!("Failed to parse HTML for {}: {}", url, e);
                            (None, None)
                        },
                    }
                } else {
                    (None, None)
                };
                
                pages_info.push(PageInfo {
                    url,
                    title,
                    description,
                });
            }
        }
    } // End processing scope
    
    CrawlDomainsResponse {
        domain: domain.to_string(),
        pages: pages_info, // Use the outer variable - now in scope
    }
}

// Add a function to clean boilerplate content
fn clean_content(text: &str, domain: &str) -> String {
    // Use case-insensitive comparison for phrases
    let text_lower = text.to_lowercase();

    // --- Normalizing Domain ---
    // Remove www. prefix if present for broader matching
    let normalized_domain = domain.trim_start_matches("www.");
    // Escape dots for regex if needed, but simple replace might be fine for domains
    let cleaned_domain = text.replace(normalized_domain, "DOMAIN"); // Replace domain

    // Remove common boilerplate phrases (case-insensitive)
    let common_phrases = vec![
        "cookie policy", "privacy policy", "terms of service",
        "all rights reserved", "copyright", "contact us",
        // Add more potentially noisy common terms found in footers/headers
        "site map", "accessibility", "careers", "about us" // Example additions
    ];

    let mut cleaned = cleaned_domain.clone(); // Start with domain-normalized text
    let cleaned_lower = cleaned_domain.to_lowercase(); // Lowercase version for phrase matching

    for phrase in common_phrases {
        if cleaned_lower.contains(phrase) {
            // Use regex for case-insensitive replacement on the original casing string
             // Create a case-insensitive regex for the phrase
            match regex::Regex::new(&format!(r"(?i){}", regex::escape(phrase))) {
                Ok(re) => {
                    cleaned = re.replace_all(&cleaned, "").to_string();
                }
                Err(e) => {
                    tracing::error!("Invalid regex pattern for phrase '{}': {}", phrase, e);
                    // Fallback to simple case-sensitive replace if regex fails
                    cleaned = cleaned.replace(phrase, "");
                 }
            }
        }
    }

    // Additional cleaning: remove excessive whitespace resulting from replacements
    cleaned = cleaned.split_whitespace().collect::<Vec<&str>>().join(" ");

    cleaned.trim().to_string()
} 