// Add this line at the top of your lib.rs file, before any imports
pub mod error;

// Then your existing imports can stay as they are
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
use std::collections::{VecDeque, HashSet};
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
use select::predicate::{Name, Attr, Predicate};
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
use chrono::{DateTime}; // Add Utc for parsing
use regex::Regex; // Already imported, ensure it's available
use chrono::TimeZone;
use crate::error::AppError;

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
        compare_domain_pages,
        research_new_pages
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
        PageMetadata,
        NewPagesQuery,
        NewPagesResponse,
        NewPageDetail,
        DetectionMethod
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
        .route("/research/pages/new/batch", post(research_new_pages_batch))
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
        if let Some(path_segments) = parsed_url.path_segments() {
            // --- EDIT: Use peekable iterator to handle language codes ---
            let mut segment_iter = path_segments.peekable();

            // --- Skip common language/region codes ---
            if let Some(first_seg) = segment_iter.peek() {
                let first_seg_lower = first_seg.to_lowercase();
                // Common patterns: xx, xx-xx, xx_XX
                let is_lang_code = (first_seg_lower.len() == 2 && first_seg_lower.chars().all(|c| c.is_ascii_alphabetic())) ||
                                   (first_seg_lower.len() == 5 && first_seg_lower.contains('-') || first_seg_lower.contains('_'));

                if is_lang_code {
                    tracing::trace!("Skipping potential language code segment: {}", first_seg_lower);
                    segment_iter.next(); // Consume the language code segment
                }
            }
            // --- END EDIT for language codes ---


            // --- Check the *first meaningful* segment ---
            if let Some(segment1_raw) = segment_iter.next() {
                // --- EDIT: Expand keywords for segment 1 ---
                let segment1 = segment1_raw.to_lowercase();
                match segment1.as_str() {
                    "blog" | "posts" | "news" | "insights" | "articles" | "press" | "releases" | "updates" => return PageType::Blog,
                    "solutions" | "services" | "platform" | "features" | "capabilities" | "offerings" => return PageType::Solution,
                    "products" | "store" | "shop" => return PageType::Product,
                    "case-studies" | "casestudies" | "customer-stories" | "success-stories" | "clients" | "portfolio" | "customers" => return PageType::CaseStudy,
                    "docs" | "documentation" | "guides" | "api" | "help" | "support" | "resources" | "whitepapers" | "reports" | "tutorials" | "knowledge-base" | "faq" => {
                        // "resources", "support", "help" can be ambiguous. Defaulting to Documentation/Support here.
                        // Title/H1 might refine later if needed, but URL is often strong signal.
                        tracing::trace!("Classified as Documentation/Resource by URL segment: {}", segment1);
                        return PageType::Documentation;
                    },
                    "legal" | "privacy" | "terms" | "imprint" | "impressum" | "cookies" | "security" | "compliance" | "disclaimer" | "terms-of-use" => return PageType::Legal,
                    "about" | "company" | "team" | "careers" | "jobs" | "mission" | "values" => return PageType::About,
                    "contact" | "locations" | "contact-us" => return PageType::Contact,
                    // --- END EDIT: Expanded keywords ---
                    _ => {
                        // --- Check the *second* meaningful segment if first wasn't decisive ---
                        if let Some(segment2_raw) = segment_iter.next() {
                            // --- EDIT: Expand keywords for segment 2 ---
                             let segment2 = segment2_raw.to_lowercase();
                             match segment2.as_str() {
                                 "blog" | "posts" | "news" | "insights" | "articles" | "press" => return PageType::Blog,
                                 "solutions" | "services" | "platform" | "features" => return PageType::Solution,
                                 "products" => return PageType::Product,
                                 "case-studies" | "casestudies" | "customer-stories" | "customers" => return PageType::CaseStudy,
                                 "docs" | "documentation" | "guides" | "api" | "resources" | "tutorials" => return PageType::Documentation,
                                  "legal" | "privacy" | "terms" => return PageType::Legal,
                                  "about" | "company" | "team" | "careers" => return PageType::About,
                                  "contact" => return PageType::Contact,
                                  // Add more second-level checks if needed
                                  _ => {}
                             }
                             // --- END EDIT: Expanded keywords ---
                        }
                    }
                }
            }
        } // end segment check

        // --- EDIT: Improved Landing Page / Homepage Detection ---
        // Check if URL path is empty or just "/" *after* checking segments
        if parsed_url.path() == "/" || parsed_url.path().is_empty() {
            // Check title for common homepage indicators or emptiness
            let host_str_lower = parsed_url.host_str().unwrap_or("").to_lowercase();
            // Check if title is simply "Home", empty, or matches the domain name
            if title_lower == "home" || title_lower.is_empty() || (title_lower == host_str_lower) || title_lower == host_str_lower.replace("www.","") {
                 tracing::trace!("Classified as LandingPage (Homepage) by path '/' and title: '{}'", title_lower);
                 return PageType::LandingPage;
            }
            // If path is "/" but title is specific (e.g., "Our Awesome Solutions"), let it fall through.
            tracing::trace!("Path is '/', but title '{}' is specific. Falling through.", title_lower);
        }
        // --- END EDIT ---

    } else {
        tracing::warn!("Failed to parse URL for classification: {}", metadata.url);
    }

    // --- Title/H1 Keyword Analysis (Fallback if URL wasn't decisive) ---
    let combined_header = format!("{} {}", h1_lower, title_lower);
    // --- EDIT: Add negative constraint check ---
    let url_likely_blog = url_lower.contains("/blog/") || url_lower.contains("/post/") || url_lower.contains("/article") || url_lower.contains("/news/");
    let url_likely_docs = url_lower.contains("/doc") || url_lower.contains("/guide") || url_lower.contains("/api"); // Simplified check
    // --- END EDIT ---


    // --- EDIT: Expand keywords and add negative constraints ---
    if combined_header.contains("blog") || combined_header.contains("post") || combined_header.contains("article") || combined_header.contains("news") || combined_header.contains("insight") || combined_header.contains("update") || combined_header.contains("release") || combined_header.contains("press") {
        // Less need for negative check here, as "blog" keywords are strong
        return PageType::Blog;
    }
    // Check Solutions/Services *only if URL doesn't strongly suggest blog*
    if !url_likely_blog && (combined_header.contains("solution") || combined_header.contains("service") || combined_header.contains("platform") || combined_header.contains("capability") || combined_header.contains("offering")) {
        tracing::trace!("Classified as Solution by title/h1 (URL not blog)");
        return PageType::Solution;
    }
    // Check Product *only if URL doesn't strongly suggest blog*
    if !url_likely_blog && (combined_header.contains("product") || combined_header.contains("store") || combined_header.contains("shop")) {
        tracing::trace!("Classified as Product by title/h1 (URL not blog)");
        return PageType::Product;
    }
    if combined_header.contains("case study") || combined_header.contains("customer story") || combined_header.contains("success story") || combined_header.contains("client results") || combined_header.contains("portfolio") {
         return PageType::CaseStudy;
    }
     // Check Docs *only if URL doesn't already suggest Docs (to avoid overly broad keywords overriding URL)*
     if !url_likely_docs && (combined_header.contains("documentation") || combined_header.contains("guide") || combined_header.contains("api reference") || combined_header.contains("resource") || combined_header.contains("whitepaper") || combined_header.contains("tutorial") || combined_header.contains("knowledge base") || combined_header.contains("faq")) {
         tracing::trace!("Classified as Documentation by title/h1 (URL not already docs)");
         return PageType::Documentation;
    }
     if combined_header.contains("privacy") || combined_header.contains("terms") || combined_header.contains("legal") || combined_header.contains("cookie policy") || combined_header.contains("compliance") || combined_header.contains("security") || combined_header.contains("disclaimer") {
         return PageType::Legal;
    }
     if combined_header.contains("about us") || combined_header.contains("company") || combined_header.contains("our team") || combined_header.contains("mission") || combined_header.contains("value") || combined_header.contains("career") || combined_header.contains("job") {
         return PageType::About;
    }
    // Check Contact last as "support" or "help" might be caught by Docs earlier if URL matched
      if combined_header.contains("contact us") || combined_header.contains("get in touch") || combined_header.contains("location") || combined_header.contains("support") || combined_header.contains("help") {
          // If it reaches here, it's likely a dedicated contact/support page rather than docs.
          return PageType::Contact;
    }
    // --- END EDIT: Expanded keywords and negative constraints ---

    // --- Fallback ---
    tracing::debug!("Could not classify page based on URL or Title/H1 heuristics, falling back to General: {}", metadata.url);
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

// --- Add helper function to parse date strings ---
// Use Lazy static for regex compilation
static DATE_PATTERN_REGEX: Lazy<Regex> = Lazy::new(|| {
    // Regex to find common date patterns like "Published on: Jan 1, 2023", "Posted: 2023-01-15", etc.
    // This is a basic example and might need significant refinement for robustness.
    // It captures potential date strings following keywords.
    Regex::new(r"(?i)(?:published|posted|created)(?:\s*on)?[:\s]+([a-zA-Z]+\s+\d{1,2},\s*\d{4}|\d{4}-\d{2}-\d{2}|\d{1,2}\s+[a-zA-Z]+\s+\d{4})")
        .expect("Failed to compile date pattern regex")
});

// More flexible parsing attempts using common formats
fn parse_flexible_date(date_str: &str) -> Option<DateTime<Utc>> {
    // Trim whitespace
    let date_str = date_str.trim();

    // Try common formats supported by chrono directly
    // Order matters: try more specific formats first
    let formats = [
        "%Y-%m-%dT%H:%M:%S%.fZ", // ISO 8601 with Zulu offset
        "%Y-%m-%dT%H:%M:%S%:z",  // ISO 8601 with timezone offset
        "%Y-%m-%d %H:%M:%S %z",
        "%a, %d %b %Y %H:%M:%S %z", // RFC 2822 style
        "%Y-%m-%d",             // Date only
        "%b %d, %Y",            // "Jan 1, 2023"
        "%d %b %Y",             // "1 Jan 2023"
        "%B %d, %Y",            // "January 1, 2023"
        "%d %B %Y",             // "1 January 2023"

    ];

    for fmt in formats.iter() {
         // --- Attempt 1: Parse as DateTime<Utc> directly ---
        if let Ok(dt_utc) = DateTime::parse_from_str(date_str, fmt).map(|dt| dt.with_timezone(&Utc)) {
            return Some(dt_utc);
        }
         // --- Attempt 2: Parse as DateTime<FixedOffset> then convert ---
        if let Ok(dt_fixed) = DateTime::parse_from_str(date_str, fmt) {
             // Check if it parsed successfully, then convert to UTC
            return Some(dt_fixed.with_timezone(&Utc));
         }
         // --- Attempt 3: Parse as NaiveDateTime then assume UTC ---
         // Be cautious with this, only use if timezone is highly likely UTC or unknown
         if let Ok(naive_dt) = chrono::NaiveDateTime::parse_from_str(date_str, fmt) {
             // Explicitly create DateTime<Utc>
             if let chrono::LocalResult::Single(dt_utc) = Utc.from_local_datetime(&naive_dt) {
                 return Some(dt_utc);
             }
         }
         // --- Attempt 4: Parse as NaiveDate then assume start of day UTC ---
         if let Ok(naive_date) = chrono::NaiveDate::parse_from_str(date_str, fmt) {
            if let Some(dt_utc) = naive_date.and_hms_opt(0, 0, 0).map(|ndt| Utc.from_utc_datetime(&ndt)) {
                return Some(dt_utc);
            }
         }
    }

    // Fallback: Try dateparser crate if chrono fails (optional dependency)
    // if let Ok(parsed_dt) = dateparser::parse(date_str) {
    //     return Some(parsed_dt.with_timezone(&Utc));
    // }

    tracing::trace!("Could not parse date string '{}' with known formats", date_str);
    None
}
// --- End date parsing helper ---


#[tracing::instrument(skip(url, client), fields(url = %url))]
async fn detect_creation_date(
    url: String,
    client: ClientWithMiddleware, // Accept the cached client
) -> Result<Option<NewPageDetail>, Box<dyn Error + Send + Sync>> {
    tracing::debug!("Fetching for date detection: {}", url);

    // --- Fetch page content ---
    // ... (fetch logic remains the same) ...
    let response = match client.get(&url).send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                resp
            } else {
                return Err(format!("HTTP status {} for {}", resp.status(), url).into());
            }
        }
        Err(e) => {
             return Err(format!("Failed to fetch {}: {}", url, e).into());
        }
    };

    let html_content = response.text().await.map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;

    // --- Parse HTML ---
    let document = Document::from(html_content.as_str());

    // --- Strategy 1: Meta Tags (Revert to using combined predicates) ---
    let checks = [
        (Name("meta").and(Attr("property", "article:published_time")), 0.9, "meta_published_time"),
        (Name("meta").and(Attr("property", "og:published_time")), 0.85, "meta_og_published_time"),
        (Name("meta").and(Attr("name", "pubdate")), 0.8, "meta_pubdate"),
        (Name("meta").and(Attr("name", "date")), 0.7, "meta_date"),
        (Name("meta").and(Attr("itemprop", "datePublished")), 0.9, "meta_itemprop_datePublished"),
    ];

    for (predicate, confidence, detail_key) in checks.iter() {
        // --- EDIT: Pass the concrete predicate type `*predicate` directly ---
        if let Some(node) = document.find(*predicate).next() { // Use *predicate
            if let Some(content) = node.attr("content") {
                if let Some(parsed_date) = parse_flexible_date(content) {
                    tracing::debug!("Found date via {}: {} ({})", detail_key, content, url);
                    return Ok(Some(NewPageDetail {
                        url: url.clone(),
                        creation_date: Some(parsed_date.to_rfc3339()),
                        confidence: *confidence,
                        detection_detail: detail_key.to_string(),
                    }));
                } else {
                    tracing::trace!("Failed to parse date from {}: {}", detail_key, content);
                }
            }
        }
        // --- END EDIT ---
    }
    // --- End Strategy 1 Revision ---


    // --- Strategy 2: JSON-LD Structured Data (Revert to using combined predicates) ---
    // --- EDIT: Combine Name and Attr predicates ---
    let json_ld_predicate = Name("script").and(Attr("type", "application/ld+json"));
    for script_node in document.find(json_ld_predicate) { // Use combined predicate
        // ... (rest of JSON-LD logic) ...
         let script_content = script_node.inner_html();
         if let Ok(json_data) = serde_json::from_str::<serde_json::Value>(&script_content) {
             let potential_date_str = json_data.get("datePublished")
                 .or_else(|| json_data.get("uploadDate"))
                 .and_then(|v| v.as_str());

             if let Some(date_str) = potential_date_str {
                 if let Some(parsed_date) = parse_flexible_date(date_str) {
                     tracing::debug!("Found date via JSON-LD: {} ({})", date_str, url);
                     return Ok(Some(NewPageDetail {
                         url: url.clone(),
                         creation_date: Some(parsed_date.to_rfc3339()),
                         confidence: 0.95,
                         detection_detail: "json_ld_date_published".to_string(),
                     }));
                 } else {
                     tracing::trace!("Failed to parse date from JSON-LD: {}", date_str);
                 }
             }
         }
    }
    // --- END EDIT ---


    // --- Strategy 3: <time> Tag (Revert to using combined predicates) ---
    // --- EDIT: Combine Name and Attr predicates, use () to check for presence ---
    let time_predicate = Name("time").and(Attr("datetime", ())); // Use combined predicate
    if let Some(time_node) = document.find(time_predicate).next() {
        // ... (rest of time tag logic) ...
         if let Some(datetime_attr) = time_node.attr("datetime") {
            if let Some(parsed_date) = parse_flexible_date(datetime_attr) {
                tracing::debug!("Found date via <time datetime>: {} ({})", datetime_attr, url);
                return Ok(Some(NewPageDetail {
                   url: url.clone(),
                   creation_date: Some(parsed_date.to_rfc3339()),
                   confidence: 0.75,
                   detection_detail: "time_datetime".to_string(),
                }));
            } else {
                tracing::trace!("Failed to parse date from <time datetime>: {}", datetime_attr);
            }
        }
    }
    // --- END EDIT ---


    // --- Strategy 4: Text Patterns (Lower Confidence) ---
    // (This uses Name directly, which is correct)
    let body_text = document.find(Name("body")).next().map(|n| n.text()).unwrap_or_default();
    // ... (rest of text pattern logic) ...
    if let Some(captures) = DATE_PATTERN_REGEX.captures(&body_text) {
        if let Some(date_match) = captures.get(1) {
            let date_str = date_match.as_str();
            if let Some(parsed_date) = parse_flexible_date(date_str) {
                tracing::debug!("Found date via text pattern: {} ({})", date_str, url);
                return Ok(Some(NewPageDetail {
                    url: url.clone(),
                    creation_date: Some(parsed_date.to_rfc3339()),
                    confidence: 0.4,
                    detection_detail: "text_pattern".to_string(),
                }));
             } else {
                 tracing::trace!("Failed to parse date from text pattern: {}", date_str);
             }
        }
    }


    // --- No Date Found ---
    tracing::debug!("No creation date found in HTML for: {}", url);
    Ok(None)
}

// ... rest of the code (parse_flexible_date, try_fetch_new_wordpress_posts, etc.) ...

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
    let start_time = Instant::now();

    if !(0.0..=1.0).contains(&request.similarity_threshold) {
         return (StatusCode::UNPROCESSABLE_ENTITY, Json(serde_json::json!({
             "error": "similarity_threshold must be between 0.0 and 1.0"
         }))).into_response();
    }

    tracing::info!("Starting semantic page comparison for {} vs {} with threshold {}",
        request.domain_a, request.domain_b, request.similarity_threshold);

    let embedder = state.embedder;
    let client = state.http_client;

    // --- Get Sitemap URLs ---
    let sitemap_url_a = match find_sitemap(&request.domain_a, client.clone()).await {
        Ok(Some(url)) => url,
        Ok(None) => {
            tracing::error!("Sitemap not found for domain_a: {}", request.domain_a);
            return (StatusCode::UNPROCESSABLE_ENTITY, Json(CompareDomainsResponse {
                domain_a: request.domain_a, domain_b: request.domain_b,
                similar_pages: vec![],
                domain_a_processing_errors: vec!["Sitemap not found".to_string()],
                domain_b_processing_errors: vec![],
            })).into_response();
        },
        Err(e) => {
            tracing::error!("Error finding sitemap for domain_a {}: {}", request.domain_a, e);
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
                domain_b_processing_errors: vec!["Sitemap not found".to_string()],
            })).into_response();
        },
        Err(e) => {
            tracing::error!("Error finding sitemap for domain_b {}: {}", request.domain_b, e);
             return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": format!("Error finding sitemap for domain_b: {}", e)}))).into_response();
        }
    };

    // --- Get All URLs from Sitemaps ---
    let urls_a = match get_all_sitemap_urls(&sitemap_url_a, client.clone()).await {
        Ok(urls) => urls,
        Err(e) => {
            tracing::error!("Error getting URLs for domain_a {}: {}", request.domain_a, e);
            return (StatusCode::UNPROCESSABLE_ENTITY, Json(serde_json::json!({ "error": format!("Error processing sitemap for domain_a: {}", e)}))).into_response();
        }
    };
     let urls_b = match get_all_sitemap_urls(&sitemap_url_b, client.clone()).await {
        Ok(urls) => urls,
         Err(e) => {
            tracing::error!("Error getting URLs for domain_b {}: {}", request.domain_b, e);
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

    // --- Fetch and Process Pages Concurrently ---
    let fetch_process_span_a = tracing::info_span!("fetch_process_embed_pages", domain = %request.domain_a);
    let embedder_a = embedder.clone();
    let client_a = client.clone();
    let futures_a = urls_a.into_iter().map(|url| {
        let client_c = client_a.clone();
        let embedder_c = embedder_a.clone();
        let url_for_span = url.clone();
        tokio::spawn(async move {
            (url.clone(), fetch_and_process_page(url, client_c, embedder_c).await)
        })
        .instrument(tracing::info_span!("process_page_task", url = %url_for_span))
    });
    let results_a = join_all(futures_a).instrument(fetch_process_span_a).await;

    let fetch_process_span_b = tracing::info_span!("fetch_process_embed_pages", domain = %request.domain_b);
    let embedder_b = embedder.clone();
    let client_b = client.clone();
    let futures_b = urls_b.into_iter().map(|url| {
        let client_c = client_b.clone();
        let embedder_c = embedder_b.clone();
        let url_for_span = url.clone();
        tokio::spawn(async move {
             (url.clone(), fetch_and_process_page(url, client_c, embedder_c).await)
        })
        .instrument(tracing::info_span!("process_page_task", url = %url_for_span))
    });
    let results_b = join_all(futures_b).instrument(fetch_process_span_b).await;


    // --- Separate successful results from errors ---
    let mut processed_a_all: Vec<ProcessedPage> = Vec::new();
    let mut errors_a: Vec<String> = Vec::new();
    for result in results_a {
        match result {
             Err(join_error) => tracing::error!("JoinError processing domain_a pages: {}", join_error),
            Ok((_url, Ok(page))) => processed_a_all.push(page),
            Ok((url, Err(e))) => {
                tracing::warn!("Failed to process URL for domain_a {}: {}", url, e);
                errors_a.push(url);
            }
        }
    }
    let mut processed_b_all: Vec<ProcessedPage> = Vec::new();
    let mut errors_b: Vec<String> = Vec::new();
     for result in results_b {
        match result {
             Err(join_error) => tracing::error!("JoinError processing domain_b pages: {}", join_error),
            Ok((_url, Ok(page))) => processed_b_all.push(page),
            Ok((url, Err(e))) => {
                tracing::warn!("Failed to process URL for domain_b {}: {}", url, e);
                errors_b.push(url);
            }
         }
    }

    let initial_count_a = processed_a_all.len();
    let initial_count_b = processed_b_all.len();

    // --- Filter out boilerplate pages ---
    processed_a_all.retain(|page| !is_boilerplate_page(page));
    processed_b_all.retain(|page| !is_boilerplate_page(page));

    let filtered_count_a = processed_a_all.len();
    let filtered_count_b = processed_b_all.len();

    tracing::info!(
        "Processing Domain A: {} initial -> {} filtered ({} errors)",
        initial_count_a, filtered_count_a, errors_a.len()
    );
    tracing::info!(
         "Processing Domain B: {} initial -> {} filtered ({} errors)",
        initial_count_b, filtered_count_b, errors_b.len()
    );


    // --- Compare ALL Processed Pages with Type Preference ---
    let mut similar_pairs: Vec<SimilarPagePair> = Vec::new();
    let comparison_span = tracing::info_span!("compare_embeddings_all");
    {
        let _enter = comparison_span.enter();
        let semantic_threshold = request.similarity_threshold;
        const TYPE_MATCH_BONUS: f64 = 0.1; // Bonus for matching types (tune as needed)

        tracing::info!(
            "Comparing all {} pages from domain A against all {} pages from domain B...",
            filtered_count_a, filtered_count_b
        );

        // Iterate through each page in domain A
        for page_a in &processed_a_all {
            // Ensure page_a has an embedding
            if let Some(embed_a) = &page_a.embedding {
                let mut best_match_for_a: Option<&ProcessedPage> = None;
                let mut highest_comparison_score_for_a = -2.0; // Initialize lower than any possible score
                let mut best_actual_similarity_for_a = -2.0;

                // Compare page_a against every page in domain B
                for page_b in &processed_b_all {
                    if let Some(embed_b) = &page_b.embedding {
                        if let Some(actual_similarity) = cosine_similarity(embed_a, embed_b) {
                            let mut comparison_score = actual_similarity;

                            // Apply bonus if types match and are meaningful
                            if page_a.page_type == page_b.page_type &&
                               page_a.page_type != PageType::General &&
                               page_a.page_type != PageType::Unknown {
                                comparison_score += TYPE_MATCH_BONUS;
                                tracing::trace!("Applied type match bonus ({}) for pair: '{}' ({:?}) vs '{}' ({:?})",
                                                TYPE_MATCH_BONUS, page_a.metadata.url, page_a.page_type,
                                                page_b.metadata.url, page_b.page_type);
                            }

                            // Check if this is the best match *for page_a* so far based on comparison score
                            if comparison_score > highest_comparison_score_for_a {
                                highest_comparison_score_for_a = comparison_score;
                                best_actual_similarity_for_a = actual_similarity;
                                best_match_for_a = Some(page_b);
                            }
                        } else {
                             tracing::warn!("Could not calculate similarity between {} and {}", page_a.metadata.url, page_b.metadata.url);
                        }
                    }
                } // End inner loop (pages_b)

                // After checking all pages_b, see if the best match meets the original threshold
                if best_actual_similarity_for_a >= semantic_threshold {
                    if let Some(matched_b) = best_match_for_a {
                        tracing::debug!("Found similar pair (score {:.4}, threshold {}): A='{}' ({:?}) | B='{}' ({:?})",
                                       best_actual_similarity_for_a, semantic_threshold,
                                       page_a.metadata.url, page_a.page_type,
                                       matched_b.metadata.url, matched_b.page_type);
                        similar_pairs.push(SimilarPagePair {
                            page_a: page_a.metadata.clone(),
                            page_b: matched_b.metadata.clone(),
                            similarity_score: best_actual_similarity_for_a, // Store the *actual* score
                        });
                    }
                }
            } else {
                tracing::debug!("Skipping comparison for page_a without embedding: {}", page_a.metadata.url);
            }
        } // End outer loop (pages_a)
    } // End comparison scope

    tracing::info!("Found {} similar page pairs above threshold {}", similar_pairs.len(), request.similarity_threshold);

    // ---> Calculate and Log Performance Metrics <---
    let total_duration = start_time.elapsed();
    let total_processed_count = filtered_count_a + filtered_count_b;
    let avg_time_per_page = if total_processed_count > 0 {
        total_duration.as_secs_f64() / total_processed_count as f64
    } else {
        0.0
    };

    tracing::info!(
        total_duration_ms = total_duration.as_millis(),
        total_pages_processed_a = filtered_count_a,
        total_pages_processed_b = filtered_count_b,
        avg_time_per_page_ms = avg_time_per_page * 1000.0,
        "Similarity comparison complete (with type preference)."
    );

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

// --- Structs and Enums for New Pages Endpoint ---

// Function to provide the default value for within_days in NewPagesQuery
fn default_within_days_new() -> u32 {
    30 // Default to checking the last 30 days for new pages
}

// --- EDIT: Ensure this struct definition is correct ---
#[derive(Debug, Deserialize, ToSchema, IntoParams)] // Add IntoParams trait
#[into_params(parameter_in = Query)] // Add this attribute
pub struct NewPagesQuery {
    /// List of domain names to analyze (max 20)
    domains: Vec<String>,
    /// Optional: Set to true to include the list of new page URLs and details in the response for each domain. Defaults to false.
    #[serde(default)]
    #[param(required = false)] // Add this attribute for query parameters
    list_pages: Option<bool>,
    /// Optional: Number of days in the past to check for newly created pages. Defaults to 30.
    #[serde(default = "default_within_days_new")]
    #[param(required = false)] // Add this attribute for query parameters
    within_days: u32,
}
// --- END EDIT ---

#[derive(Debug, Serialize, ToSchema, Clone)]
pub struct NewPageDetail {
    /// URL of the newly detected page
    url: String,
    /// Detected creation date (ISO 8601 format)
    creation_date: Option<String>,
    /// Confidence score for the detected date (0.0 - 1.0)
    confidence: f32,
    /// Specific method used for detection (e.g., "meta_published_time", "json_ld_date_published", "text_pattern")
    detection_detail: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub enum DetectionMethod {
    SitemapLastmod,
    WordPressApi,
    HtmlAnalysis,
    Mixed, // If multiple methods contributed
    None, // If no method could be applied (e.g., only sitemap URL found)
}

#[derive(Debug, Serialize, ToSchema)]
pub struct NewPagesResponse {
    /// Domain that was analyzed
    domain: String,
    /// Number of newly created pages found within the specified period
    new_pages_count: i32,
    /// Number of days analyzed (period in the past)
    days_analyzed: u32,
    /// Primary detection method used (summary)
    detection_method: DetectionMethod,
    /// URL of the sitemap that was analyzed (if found)
    sitemap_url: Option<String>,
    /// Optional: List of URLs for pages identified as new (present if list_pages=true)
    #[serde(skip_serializing_if = "Option::is_none")]
    new_page_urls: Option<Vec<String>>,
    /// Optional: Detailed information about new pages (present if list_pages=true)
    #[serde(skip_serializing_if = "Option::is_none")]
    new_page_details: Option<Vec<NewPageDetail>>,
    /// URLs from the sitemap that failed during processing (e.g., fetching, date extraction)
    processing_errors: Vec<String>,
}

/// Get newly created pages within a specified number of days for a given domain
#[utoipa::path(
    get,
    path = "/research/pages/new",
    params(NewPagesQuery),
    responses(
        (status = 200, description = "Success, analysis complete", body = NewPagesResponse),
        (status = 422, description = "Unprocessable Entity - Sitemap not found or processing error", body = NewPagesResponse),
        (status = 500, description = "Internal Server Error during processing")
    ),
    description = "Attempts to identify web pages created within a specific number of days by analyzing sitemaps, HTML metadata, and potentially CMS APIs."
)]
#[tracing::instrument(skip(query, state), fields(domain = ?query.domains, days = %query.within_days))]
async fn research_new_pages(
    Query(query): Query<NewPagesQuery>,
    State(state): State<AppState> // Inject AppState
) -> impl IntoResponse {
    let start_time = Instant::now();
    let days_to_analyze = query.within_days;
    // Calculate the cutoff date (inclusive)
    let cutoff_date = Utc::now() - Duration::days(days_to_analyze as i64);
    let should_list_pages = query.list_pages.unwrap_or(false);

    tracing::info!(
        "Analyzing {:?} for the past {} days (before {})", // Changed {} to {:?} for domains
        query.domains, days_to_analyze, cutoff_date.to_rfc3339());

    let client = state.http_client.clone(); // Use client from state

    // --- Initialize Response ---
    // Renamed field to be more descriptive
    let mut response_body = NewPagesResponse {
        domain: query.domains.first().cloned().unwrap_or_default(), // Take the first domain, or empty string
        new_pages_count: 0, // Initialize count
        days_analyzed: days_to_analyze,
        detection_method: DetectionMethod::None, // Start with None
        sitemap_url: None,
        new_page_urls: if should_list_pages { Some(Vec::new()) } else { None },
        new_page_details: if should_list_pages { Some(Vec::new()) } else { None },
        processing_errors: Vec::new(),
    };

    // --- 1. Find Sitemap ---
    let domain_to_check = query.domains.first().cloned().unwrap_or_default();
    let sitemap_url_result = find_sitemap(&domain_to_check, client.clone()).await;
    // ... (existing sitemap finding logic remains the same) ...
     let sitemap_url = match sitemap_url_result {
        Ok(Some(url)) => {
            response_body.sitemap_url = Some(url.clone());
            tracing::info!("Found sitemap: {}", url);
            url
        },
        Ok(None) => {
            tracing::warn!("Sitemap not found for {:?}", query.domains); // Changed {} to {:?} for domains
            response_body.processing_errors.push("Sitemap not found".to_string());
            return (StatusCode::UNPROCESSABLE_ENTITY, Json(response_body)).into_response();
        },
        Err(e) => {
            tracing::error!("Error finding sitemap for {:?}: {}", query.domains, e); // Changed {} to {:?} for domains
            response_body.processing_errors.push(format!("Error finding sitemap: {}", e));
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(response_body)).into_response();
        }
    };


    // --- 2. Get All URLs from Sitemap ---
    let all_urls_result = get_all_sitemap_urls(&sitemap_url, client.clone()).await;
    // ... (existing URL extraction logic remains the same) ...
     let urls_to_check = match all_urls_result {
        Ok(urls) => {
            if urls.is_empty() {
                tracing::warn!("Sitemap found but contained no URLs: {}", sitemap_url);
                 return (StatusCode::OK, Json(response_body)).into_response();
            }
            tracing::info!("Found {} URLs in sitemap(s) to analyze", urls.len());
            urls
        },
        Err(e) => {
            tracing::error!("Error extracting URLs from sitemap {}: {}", sitemap_url, e);
            response_body.processing_errors.push(format!("Error reading sitemap: {}", e));
            return (StatusCode::UNPROCESSABLE_ENTITY, Json(response_body)).into_response();
        }
    };


    // --- 3. Process URLs Concurrently ---
    let detection_futures = urls_to_check.into_iter().map(|url| {
        let client_clone = client.clone();
        let url_clone = url.clone(); // Clone URL for the async block
        tokio::spawn(async move {
            (url_clone, detect_creation_date(url, client_clone).await)
        })
    });

    let detection_span = tracing::info_span!("detect_creation_dates", url_count = detection_futures.len());
    let detection_results = join_all(detection_futures).instrument(detection_span).await;

    // --- 4. Collect Results and Filter ---
    let mut found_valid_date = false; // Track if any date was successfully detected and parsed

    for result in detection_results {
        match result {
            Err(join_error) => {
                // Log join errors (panics in spawned tasks)
                tracing::error!("JoinError during date detection: {}", join_error);
                // Optionally add a generic error or try to extract URL if possible
                response_body.processing_errors.push("Task panic during processing".to_string());
            }
            Ok((url, Ok(Some(detail)))) => {
                // Successfully fetched and found a date
                if let Some(creation_date_str) = &detail.creation_date {
                    // Attempt to parse the date string back to DateTime<Utc>
                     match DateTime::parse_from_rfc3339(creation_date_str) {
                        Ok(parsed_date) => {
                             found_valid_date = true; // Mark that we used HTML analysis
                            let creation_date_utc = parsed_date.with_timezone(&Utc);

                            // Check if the date is within the desired range (inclusive)
                            if creation_date_utc >= cutoff_date {
                                tracing::debug!("New page detected: {} (Date: {}, Method: {}, Confidence: {:.2})",
                                    detail.url, creation_date_utc.to_rfc3339(), detail.detection_detail, detail.confidence);
                                response_body.new_pages_count += 1;
                                if should_list_pages {
                                    // Add to lists only if requested
                                     if let Some(urls) = response_body.new_page_urls.as_mut() {
                                         urls.push(detail.url.clone());
                                     }
                                    if let Some(details) = response_body.new_page_details.as_mut() {
                                         details.push(detail);
                                     }
                                }
                            } else {
                                 tracing::trace!("Page date {} is outside the cutoff {} for {}", creation_date_utc.to_rfc3339(), cutoff_date.to_rfc3339(), url);
                            }
                        }
                        Err(parse_err) => {
                            // Log if the date string from NewPageDetail couldn't be parsed back
                            tracing::error!("Failed to parse stored date string '{}' for {}: {}", creation_date_str, url, parse_err);
                             response_body.processing_errors.push(url); // Add URL to errors if date parsing failed
                        }
                    }
                } else {
                    // Should not happen if detail is Some, but handle defensively
                     tracing::warn!("NewPageDetail present but creation_date is None for {}", url);
                    // Don't count as an error unless needed
                }
            }
            Ok((url, Ok(None))) => {
                // Successfully fetched, but no date found in HTML
                 tracing::trace!("No date information found in HTML for {}", url);
                 found_valid_date = true; // Mark that we used HTML analysis, even if no date was found for *this* page
            }
            Ok((url, Err(e))) => {
                // Error fetching or processing the specific URL
                tracing::warn!("Failed to process URL for date detection {}: {}", url, e);
                response_body.processing_errors.push(url);
            }
        }
    }

     // --- 5. Set Final Detection Method ---
     if found_valid_date {
         // We successfully attempted HTML analysis on at least one page
         response_body.detection_method = DetectionMethod::HtmlAnalysis;
         // TODO: In the future, if we add WordPress API checks or Sitemap lastmod checks,
         // this logic would need to be updated to potentially set Mixed or WordPressApi, etc.
     } else if response_body.sitemap_url.is_some() && response_body.processing_errors.is_empty() {
          // If we only had a sitemap and no URLs could be processed for dates (e.g., all failed fetch)
          // Or if get_all_sitemap_urls returned Ok but empty vec initially (handled earlier)
          // Keep as None or potentially add a SitemapOnly status if needed
          tracing::debug!("Analysis completed, but no date information could be extracted via HTML.");
     }
     // If errors occurred but no dates found, method remains None or reflects partial success if any page worked.

    // --- Finalize and Return ---
    // ... (existing logging and return logic) ...
    let duration = start_time.elapsed();
    tracing::info!(
        domain = ?query.domains, // Change from % to ?
        new_pages_found = response_body.new_pages_count,
        pages_analyzed = response_body.new_page_details.as_ref().map_or(0, |d| d.len()) + response_body.processing_errors.len(),
        errors = response_body.processing_errors.len(),
        duration_ms = duration.as_millis(),
        detection_method = ?response_body.detection_method,
        "New page analysis complete."
    );

    (StatusCode::OK, Json(response_body)).into_response()
}

#[utoipa::path(
    post, // Method is POST
    path = "/research/pages/new/batch", // Path matches
    request_body = NewPagesQuery,
    responses(
        (status = 200, description = "Success, analysis complete for all requested domains", body = Vec<NewPagesResponse>),
        (status = 422, description = "Unprocessable Entity - Invalid input (e.g., too many domains)", body = String),
        (status = 500, description = "Internal Server Error during processing for one or more domains")
    ),
    description = "..."
)]
#[tracing::instrument(skip(query, state), fields(domains = ?query.domains, days = %query.within_days))] // Changed field name 'domain' to 'domains' and formatter '%' to '?'
async fn research_new_pages_batch( // Function name matches
    State(state): State<AppState>,
    Json(query): Json<NewPagesQuery> // query is Json<NewPagesQuery> here
) -> impl IntoResponse {
    // --- EDIT: Add logging inside the function body ---
    // Now 'query' refers to the extracted NewPagesQuery struct
    tracing::info!(domains_count = query.domains.len(), days = query.within_days, "Received batch request for new pages");
    // --- END EDIT ---

    let start_time = Instant::now();
    const MAX_DOMAINS: usize = 20;

    if query.domains.is_empty() {
        // ... error handling ...
    }
    if query.domains.len() > MAX_DOMAINS {
        // ... error handling ...
    }

    let client = state.http_client.clone();
    let days_to_analyze = query.within_days;
    let should_list_pages = query.list_pages.unwrap_or(false);

    // Process domains concurrently
    let analysis_futures = query.domains.into_iter().map(|domain| {
        let client_clone = client.clone();
        // Calculate the cutoff date (inclusive)
        let cutoff_date = Utc::now() - Duration::days(days_to_analyze as i64);
        tokio::spawn(async move {
             analyze_single_domain_for_new_pages(
                 domain, 
                 days_to_analyze.into(), // Convert u32 to u64
                 should_list_pages,
                 cutoff_date,           // Add the missing cutoff_date argument
                 client_clone
             ).await
        })
    });

    // ... rest of the function remains the same ...

    let batch_span = tracing::info_span!("analyze_domain_batch");
    let task_results = join_all(analysis_futures)
        .instrument(batch_span)
        .await;

    let mut final_responses: Vec<NewPagesResponse> = Vec::new();
    for result in task_results {
        match result {
            Ok(Ok(response)) => {
                final_responses.push(response);
            },
            Ok(Err(e)) => {
                tracing::error!("Error analyzing domain: {}", e);
                // Optionally add a dummy/error response here
            },
            Err(e) => {
                tracing::error!("Task join error: {}", e);
                // Optionally add a dummy/error response here
            }
        }
    }

    let duration = start_time.elapsed();
    // Note: The final log here doesn't need the count as it was logged at the start
    tracing::info!(
        total_domains_processed = final_responses.len(),
        duration_ms = duration.as_millis(),
        "Batch new page analysis complete."
    );

    (StatusCode::OK, Json(final_responses)).into_response()
}

// ... other functions ...

// --- EDIT: Make sure this function definition exists ---
#[tracing::instrument(skip(client), fields(domain = %domain, days = %days_to_analyze))] // Changed field name 'domain' to 'domains' and formatter '%' to '?'
async fn analyze_single_domain_for_new_pages(
    domain: String,
    days_to_analyze: u64,
    should_list_pages: bool,
    cutoff_date: DateTime<Utc>,
    client: ClientWithMiddleware,
) -> Result<NewPagesResponse, AppError> {
    tracing::info!("Starting analysis for single domain: {}", domain);
    
    // Ensure domain has protocol and no trailing slash
    let base_url = if !domain.starts_with("http") {
        format!("https://{}", domain)
    } else {
        // Remove potential trailing slash for consistent URL building
        domain.trim_end_matches('/').to_string()
    };
    
    // Find sitemap for this domain
    let sitemap_url = match find_sitemap(&domain, client.clone()).await {
        Ok(Some(url)) => url,
        Ok(None) => {
            tracing::warn!("No sitemap found for domain: {}", domain);
            // Continue execution, as we'll try other methods
            String::new()
        },
        Err(e) => {
            tracing::warn!("Error finding sitemap for {}: {}", domain, e);
            // Continue execution, as we'll try other methods
            String::new()
        }
    };

    // Initialize response with basic fields
    let mut response = NewPagesResponse {
        domain: domain.clone(),
        new_pages_count: 0,
        days_analyzed: days_to_analyze as u32, // Convert back to u32
        detection_method: DetectionMethod::None,
        sitemap_url: if sitemap_url.is_empty() { None } else { Some(sitemap_url.clone()) },
        new_page_urls: if should_list_pages { Some(Vec::new()) } else { None },
        new_page_details: if should_list_pages { Some(Vec::new()) } else { None },
        processing_errors: Vec::new(),
    };
    
    // First, try WordPress API - we'll try both with and without www. prefix
    let base_url_www = if base_url.contains("://www.") {
        base_url.clone()
    } else {
        base_url.replace("://", "://www.")
    };
    
    // Create both URLs to try - with and without www
    let wp_api_urls = vec![
        format!("{}/wp-json/wp/v2/posts", base_url),
        format!("{}/wp-json/wp/v2/posts", base_url_www)
    ];
    
    let mut found_wordpress = false;
    
    tracing::info!("Trying WordPress API for domain: {}", domain);
    
    // Try both URLs
    for wp_api_url in wp_api_urls {
        tracing::info!("Trying WordPress API at: {}", wp_api_url);
        
        // Try to detect WordPress API with a realistic Chrome user agent
        let user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";
        tracing::debug!("Using User-Agent: {}", user_agent);
        
        match client.get(&wp_api_url)
            .header("User-Agent", user_agent)
            .query(&[("per_page", "10"), ("after", cutoff_date.format("%Y-%m-%dT%H:%M:%S").to_string().as_str())])
            .send()
            .await {
            Ok(res) => {
                if res.status().is_success() {
                    tracing::info!("Found WordPress API at URL: {}", wp_api_url);
                    match res.json::<serde_json::Value>().await {
                        Ok(posts) => {
                            if let Some(posts_array) = posts.as_array() {
                                tracing::info!("WordPress API returned {} posts for domain: {}", posts_array.len(), domain);
                                found_wordpress = true;
                                response.detection_method = DetectionMethod::WordPressApi;
                                response.new_pages_count = posts_array.len() as i32;
                                
                                if should_list_pages && response.new_pages_count > 0 {
                                    for post in posts_array {
                                        if let (Some(link), Some(date), Some(title)) = (
                                            post.get("link").and_then(|l| l.as_str()),
                                            post.get("date").and_then(|d| d.as_str()),
                                            post.get("title").and_then(|t| t.get("rendered")).and_then(|r| r.as_str())
                                        ) {
                                            if let Some(parsed_date) = parse_flexible_date(date) {
                                                if let Some(urls) = response.new_page_urls.as_mut() {
                                                    urls.push(link.to_string());
                                                }
                                                
                                                if let Some(details) = response.new_page_details.as_mut() {
                                                    details.push(NewPageDetail {
                                                        url: link.to_string(),
                                                        creation_date: Some(parsed_date.to_rfc3339()),
                                                        confidence: 0.95,
                                                        detection_detail: format!("wordpress_api_post: {}", title),
                                                    });
                                                }
                                            }
                                        }
                                    }
                                }
                                // If we found WordPress API, break out of the loop
                                break;
                            }
                        },
                        Err(e) => {
                            tracing::warn!("Failed to parse WordPress API response for {}: {}", wp_api_url, e);
                        }
                    }
                } else {
                    tracing::info!("WordPress API not found or returned error for URL {}: {}", wp_api_url, res.status());
                }
            },
            Err(e) => {
                tracing::info!("Error accessing WordPress API at URL {}: {}", wp_api_url, e);
            }
        }
    }
    
    // If WordPress API detection was successful, return early
    if found_wordpress {
        tracing::info!("Successfully detected WordPress site for domain: {}", domain);
        return Ok(response);
    }
    
    // If WordPress detection failed and we have a sitemap, fall back to sitemap analysis
    if !sitemap_url.is_empty() {
        // Get URLs from sitemap
        let urls_to_check = match get_all_sitemap_urls(&sitemap_url, client.clone()).await {
            Ok(urls) => {
                if urls.is_empty() {
                    tracing::warn!("Sitemap found but contained no URLs: {}", sitemap_url);
                    return Ok(response);
                }
                
                tracing::info!("Processing {} URLs from sitemap for domain: {}", urls.len(), domain);
                urls
            },
            Err(e) => {
                tracing::error!("Error extracting URLs from sitemap for {}: {}", domain, e);
                response.processing_errors.push(format!("Failed to extract URLs from sitemap: {}", e));
                return Ok(response);
            }
        };
        
        // Process each URL to detect creation dates
        let mut detection_tasks = Vec::new();
        let mut found_valid_date = false;
        
        // Create detection tasks for each URL
        for url in urls_to_check {
            let client_clone = client.clone();
            detection_tasks.push(tokio::spawn(async move {
                (url.clone(), detect_creation_date(url.clone(), client_clone).await)
            }));
        }
        
        // Wait for all tasks to complete
        let detection_results = join_all(detection_tasks).await;
        
        // Process results
        for result in detection_results {
            match result {
                Ok((url, Ok(Some(detail)))) => {
                    // If we found a date for this URL
                    if let Some(creation_date_str) = &detail.creation_date {
                        match chrono::DateTime::parse_from_rfc3339(creation_date_str) {
                            Ok(parsed_date) => {
                                found_valid_date = true;
                                let creation_date_utc = parsed_date.with_timezone(&Utc);
                                
                                // Check if the date is within the desired range
                                if creation_date_utc >= cutoff_date {
                                    tracing::debug!("New page detected for {}: {} (Date: {}, Method: {})", 
                                        domain, detail.url, creation_date_str, detail.detection_detail);
                                    response.new_pages_count += 1;
                                    
                                    if should_list_pages {
                                        if let Some(urls) = response.new_page_urls.as_mut() {
                                            urls.push(detail.url.clone());
                                        }
                                        if let Some(details) = response.new_page_details.as_mut() {
                                            details.push(detail);
                                        }
                                    }
                                } else {
                                    tracing::trace!("Page date {} is outside cutoff {} for {}", 
                                        creation_date_utc.to_rfc3339(), cutoff_date.to_rfc3339(), url);
                                }
                            },
                            Err(e) => {
                                tracing::error!("Failed to parse date string '{}' for {}: {}", 
                                    creation_date_str, url, e);
                                response.processing_errors.push(url);
                            }
                        }
                    }
                },
                Ok((url, Ok(None))) => {
                    tracing::trace!("No date information found in HTML for {}", url);
                    found_valid_date = true; // Mark that we attempted HTML analysis
                },
                Ok((url, Err(e))) => {
                    tracing::warn!("Failed to process URL for date detection {}: {}", url, e);
                    response.processing_errors.push(url);
                },
                Err(e) => {
                    tracing::error!("Task join error: {}", e);
                    // Can't add URL to errors as we don't have it here
                }
            }
        }
        
        // Set detection method if we used HTML analysis
        if found_valid_date {
            response.detection_method = DetectionMethod::HtmlAnalysis;
        }
    }
    
    // Return the response, which might just have basic info if no detection methods worked
    Ok(response)
}
// --- END EDIT ---

// In analyze_multiple_domains_for_new_pages function:
pub async fn analyze_multiple_domains_for_new_pages(
    State(state): State<AppState>,
    Json(query): Json<NewPagesQuery>
) -> Result<Json<Vec<NewPagesResponse>>, AppError> {
    tracing::info!(domains_count = query.domains.len(), days = query.within_days, "Received batch analysis request");
    
    let days_to_analyze = query.within_days; // Just use the value directly
    let should_list_pages = query.list_pages.unwrap_or(false);
    // Calculate the cutoff date (inclusive)
    let cutoff_date = Utc::now() - Duration::days(days_to_analyze as i64);
    
    let client = state.http_client.clone();
    let mut tasks = Vec::new();

    // Create tasks for each domain
    for domain in query.domains {
        let task_client = client.clone();
        let cutoff_date_clone = cutoff_date;
        let should_list_pages_clone = should_list_pages;

        tasks.push(tokio::spawn(async move {
            analyze_single_domain_for_new_pages(
                domain,
                days_to_analyze.into(), // Convert u32 to u64
                should_list_pages_clone,
                cutoff_date_clone,
                task_client,
            )
            .await
        }));
    }

    // Wait for all tasks to complete
    let task_results = join_all(tasks).await;
    
    // Process results
    let mut results = Vec::new();
    let mut successful_analyses = 0;
    let mut failed_analyses = 0;
    
    for task_result in task_results {
        match task_result {
            Ok(Ok(response)) => {
                results.push(response);
                successful_analyses += 1;
            },
            Ok(Err(e)) => {
                tracing::error!("Error analyzing domain: {}", e);
                failed_analyses += 1;
            },
            Err(e) => {
                tracing::error!("Task join error: {}", e);
                failed_analyses += 1;
            }
        }
    }

    // Log the results
    tracing::info!(
        total_domains_requested = results.len() + failed_analyses,
        successful_analyses = successful_analyses,
        failed_analyses = failed_analyses,
        "Batch new page analysis processing complete."
    );

    Ok(Json(results))
}