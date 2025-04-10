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

// --- Define AppState AFTER TEXT_EMBEDDER and AFTER imports, but BEFORE functions ---
#[derive(Clone)]
struct AppState {
    embedder: Arc<Embedder>,
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
#[tracing::instrument(skip(query), fields(domain = %query.domain))]
async fn research_pages(Query(query): Query<ResearchQuery>) -> impl IntoResponse {
    let sitemap_result = find_sitemap(&query.domain).await;

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
            match count_recent_pages(&sitemap_url, days_to_analyze).await {
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
#[tracing::instrument(skip(domain), fields(domain = %domain))]
async fn find_sitemap(domain: &str) -> Result<Option<String>, Box<dyn Error + Send + Sync>> {
    // Ensure domain has protocol and no trailing slash
    let base_url = if !domain.starts_with("http") {
        format!("https://{}", domain)
    } else {
        // Remove potential trailing slash for consistent URL building
        domain.trim_end_matches('/').to_string()
    };

    // 1. Try fetching and parsing robots.txt
    let robots_url = format!("{}/robots.txt", base_url);
    tracing::info!("Attempting to fetch robots.txt from: {}", robots_url);

    match reqwest::get(&robots_url).await {
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
        // Use HEAD request to check existence efficiently without downloading the body
        match reqwest::Client::new().head(&url).send().await {
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
#[tracing::instrument(skip(initial_sitemap_url), fields(initial_sitemap_url = %initial_sitemap_url, days = %days))]
async fn count_recent_pages(initial_sitemap_url: &str, days: u32) -> Result<(i32, Vec<String>), Box<dyn Error + Send + Sync>> {
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

        let sitemap_response = match reqwest::get(&sitemap_url).await {
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

    // Create the application state
    let app_state = AppState { embedder: shared_embedder };

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

#[derive(Debug, Clone)]
struct ProcessedPage {
    metadata: PageMetadata,
    embedding: Option<Vec<f32>>,
    h1: Option<String>,
    meta_description: Option<String>,
    intro_text: String,
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

#[tracing::instrument(skip(initial_sitemap_url), fields(initial_sitemap_url = %initial_sitemap_url))]
async fn get_all_sitemap_urls(initial_sitemap_url: &str) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
    let mut all_page_urls: Vec<String> = Vec::new();
    let mut sitemap_queue: VecDeque<String> = VecDeque::new();
    sitemap_queue.push_back(initial_sitemap_url.to_string());
    let mut processed_sitemaps: HashSet<String> = HashSet::new();
    let client = Client::new();

    while let Some(sitemap_url) = sitemap_queue.pop_front() {
        if !processed_sitemaps.insert(sitemap_url.clone()) {
            tracing::debug!("Skipping already processed sitemap: {}", sitemap_url);
            continue;
        }
        tracing::info!("Processing sitemap: {}", sitemap_url);

        let sitemap_response = match client.get(&sitemap_url).send().await {
            Ok(res) => res,
            Err(e) => {
                tracing::error!("Failed to fetch sitemap {}: {}", sitemap_url, e);
                return Err(format!("Failed to fetch sitemap {}: {}", sitemap_url, e).into());
            }
        };

        if !sitemap_response.status().is_success() {
            tracing::warn!("Failed to fetch sitemap {} - Status: {}", sitemap_url, sitemap_response.status());
            return Err(format!("Failed to fetch sitemap {} - Status: {}", sitemap_url, sitemap_response.status()).into());
        }

        let sitemap_content = match sitemap_response.bytes().await {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!("Failed to read bytes from sitemap {}: {}", sitemap_url, e);
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
                }
            }
        }
    }

    tracing::info!("Found {} total page URLs in sitemap(s) starting from {}", all_page_urls.len(), initial_sitemap_url);
    Ok(all_page_urls)
}

// --- Backoff notification handler ---
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
// --- End backoff notification handler ---

// --- Helper Function for Cosine Similarity (from your suggestion) ---
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
// --- End Helper Function ---

#[tracing::instrument(skip(url, client, embedder), fields(url = %url))]
async fn fetch_and_process_page(
    url: String,
    client: Client,
    embedder: Arc<Embedder>
) -> Result<ProcessedPage, Box<dyn Error + Send + Sync>> {
    tracing::debug!("Fetching: {}", url);

    let backoff = ExponentialBackoff::default();

    // Timing the whole function includes retries and processing
    let response = retry_notify(
        backoff,
        || async {
            // Remove '?' and handle the result explicitly
            match client.get(&url).send().await {
                Ok(resp) => {
                    // --- Request was successful, now check status code ---
                    let status = resp.status();
                    if status.is_success() {
                        Ok(resp) // Success!
                    } else if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
                        // Server returned a status indicating a transient issue
                        tracing::debug!("Retrying on status: {}", status);
                        Err(BackoffError::transient(anyhow::anyhow!(
                            "Server returned retryable status: {}",
                            status
                        )))
                    } else {
                        // Server returned a status indicating a permanent issue
                        tracing::debug!("Permanent error status: {}", status);
                        Err(BackoffError::permanent(anyhow::anyhow!(
                            "Server returned non-retryable status: {}",
                            status
                        )))
                    }
                    // --- End status code check ---
                }
                Err(err) => {
                    // --- Request itself failed (network error, timeout, etc.) ---
                    // Decide if the reqwest::Error is transient or permanent
                    if err.is_timeout() || err.is_connect() || err.is_request() {
                        // Treat timeouts, connection errors, and request build errors as potentially transient
                        tracing::debug!("Retrying on reqwest error: {}", err);
                        Err(BackoffError::transient(anyhow::Error::new(err))) // Wrap the reqwest::Error
                    } else {
                        // Treat other errors (like decoding, redirects, etc.) as permanent for this retry logic
                        tracing::debug!("Permanent reqwest error: {}", err);
                        Err(BackoffError::permanent(anyhow::Error::new(err))) // Wrap the reqwest::Error
                    }
                    // --- End reqwest::Error handling ---
                }
            }
        },
        retry_notify_handler,
    )
    .await?;

    // --- Original Processing Logic (after successful fetch) ---
    let processing_span = tracing::info_span!("blocking_extraction"); // Span for blocking extraction only
    let html_content = response.text().await?;
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
        let parsed_url_for_extract = Url::parse(&url_for_blocking)?;
        let intro_text = match extractor::extract(&mut html_content.as_bytes(), &parsed_url_for_extract) {
            Ok(product) => {
                // Basic HTML to text conversion - Handle the Result
                let plain_text_result = html2text::from_read(product.content.as_bytes(), 120);
                // Use unwrap_or_default to get an empty string if conversion fails
                let plain_text = plain_text_result.unwrap_or_default();
                // Now call split_whitespace on the String
                plain_text.split_whitespace().take(200).collect::<Vec<&str>>().join(" ")
            }
            Err(e) => {
                tracing::warn!("llm_readability failed for {}: {}", url_for_blocking, e);
                String::new()
            }
        };

        // --- Construct Representative Text ---
        let representative_text = format!(
            "{} {} {} {}",
            title.as_deref().unwrap_or(""),
            h1.as_deref().unwrap_or(""),
            meta_description.as_deref().unwrap_or(""),
            intro_text
        ).trim().to_string(); // Trim potential leading/trailing whitespace

        tracing::debug!(url = %url_for_blocking, text_len = representative_text.len(), "Generated representative text");

        // Return extracted components
        Ok::<_, Box<dyn Error + Send + Sync>>((
            representative_text,
            title,
            h1, // Ensure h1 is returned
            meta_description, // Ensure meta_description is returned
            intro_text, // Ensure intro_text is returned
        ))
    }).await??;

    let (representative_text_str, page_title, page_h1, page_meta_desc, page_intro) = extracted_data;

    // --- Step 4 (Outside spawn_blocking): Generate Embedding ---
    let embedding_option: Option<Vec<f32>> = if !representative_text_str.is_empty() {
        let text_to_embed: [&str; 1] = [&representative_text_str];
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
                None
            }
        }
    } else {
        tracing::warn!("No representative text to embed for: {}", original_url_string);
        None
    };

    // --- Step 5: Create ProcessedPage ---
    Ok(ProcessedPage {
        metadata: PageMetadata {
            url: original_url_string,
            title: page_title,
        },
        embedding: embedding_option, // This should now be Option<Vec<f32>>
        h1: page_h1,
        meta_description: page_meta_desc,
        intro_text: page_intro,
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

    // --- Get Sitemap URLs (remains the same) ---
    let sitemap_url_a = match find_sitemap(&request.domain_a).await {
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
    let sitemap_url_b = match find_sitemap(&request.domain_b).await {
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

    // --- Get All URLs from Sitemaps (remains the same) ---
    let urls_a = match get_all_sitemap_urls(&sitemap_url_a).await {
        Ok(urls) => urls,
        Err(e) => {
            tracing::error!("Error getting URLs for domain_a {}: {}", request.domain_a, e);
            // Return simple JSON string for unprocessable entity errors related to sitemap processing
            return (StatusCode::UNPROCESSABLE_ENTITY, Json(serde_json::json!({ "error": format!("Error processing sitemap for domain_a: {}", e)}))).into_response();
        }
    };
     let urls_b = match get_all_sitemap_urls(&sitemap_url_b).await {
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

    // --- Fetch and Process Pages Concurrently (Pass embedder) ---
    let client = Client::new();
    let fetch_process_span_a = tracing::info_span!("fetch_process_embed_pages", domain = %request.domain_a);
    let embedder_a = embedder.clone();
    let futures_a = urls_a.into_iter().map(|url| {
        let client = client.clone();
        let embedder_c = embedder_a.clone();
        // Clone url *before* the closure moves the original url
        let url_for_span = url.clone();
        tokio::spawn(async move {
            // url.clone() inside here clones the *moved* url for the function call
            (url.clone(), fetch_and_process_page(url, client, embedder_c).await)
        })
        // Use the clone created *outside* the async block for instrumentation
        .instrument(tracing::info_span!("process_page_task", url = %url_for_span))
    });
    let results_a = join_all(futures_a).instrument(fetch_process_span_a).await;


    let fetch_process_span_b = tracing::info_span!("fetch_process_embed_pages", domain = %request.domain_b);
    let embedder_b = embedder.clone();
    let futures_b = urls_b.into_iter().map(|url| {
        let client = client.clone();
        let embedder_c = embedder_b.clone();
        // Clone url *before* the closure moves the original url
        let url_for_span = url.clone();
        tokio::spawn(async move {
            // url.clone() inside here clones the *moved* url for the function call
             (url.clone(), fetch_and_process_page(url, client, embedder_c).await)
        })
        // Use the clone created *outside* the async block for instrumentation
        .instrument(tracing::info_span!("process_page_task", url = %url_for_span))
    });
    let results_b = join_all(futures_b).instrument(fetch_process_span_b).await;


    // --- Separate successful results from errors ---
    let mut processed_a: Vec<ProcessedPage> = Vec::new();
    let mut errors_a: Vec<String> = Vec::new();
    for result in results_a {
        match result {
             // Handle JoinError first
             Err(join_error) => tracing::error!("JoinError processing domain_a pages: {}", join_error),
             // Handle Result from fetch_and_process_page
            Ok((url, Ok(page))) => processed_a.push(page),
            Ok((url, Err(e))) => {
                tracing::warn!("Failed to process URL for domain_a {}: {}", url, e);
                errors_a.push(url);
            }
        }
    }
    // ... similar separation logic for results_b ...
    let mut processed_b: Vec<ProcessedPage> = Vec::new();
    let mut errors_b: Vec<String> = Vec::new();
     for result in results_b {
        match result {
             Err(join_error) => tracing::error!("JoinError processing domain_b pages: {}", join_error),
            Ok((url, Ok(page))) => processed_b.push(page),
            Ok((url, Err(e))) => {
                tracing::warn!("Failed to process URL for domain_b {}: {}", url, e);
                errors_b.push(url);
            }
         }
    }

    tracing::info!("Processed {} pages for domain A ({} errors), {} pages for domain B ({} errors)",
        processed_a.len(), errors_a.len(), processed_b.len(), errors_b.len());

    // --- Compare Processed Pages using Embeddings ---
    let mut similar_pairs: Vec<SimilarPagePair> = Vec::new();
    let comparison_span = tracing::info_span!("compare_embeddings"); // Renamed span
    {
        let _enter = comparison_span.enter(); // Time the synchronous comparison loop
        let semantic_threshold = request.similarity_threshold; // Use the threshold from request

        for page_a in &processed_a {
            // Only compare if page_a has an embedding
            if let Some(embed_a) = &page_a.embedding {
            let mut best_match_for_a: Option<&ProcessedPage> = None;
                let mut highest_similarity_for_a = -2.0; // Initialize below valid cosine range (-1 to 1)

            for page_b in &processed_b {
                    // Only compare if page_b has an embedding
                    if let Some(embed_b) = &page_b.embedding {

                        // Calculate cosine similarity using the helper
                        if let Some(similarity) = cosine_similarity(embed_a, embed_b) {
                             // Add debug logging for individual comparisons if needed
                             // tracing::trace!("Comparing {} vs {}: Score {:.4}", page_a.metadata.url, page_b.metadata.url, similarity);
                if similarity > highest_similarity_for_a {
                    highest_similarity_for_a = similarity;
                    best_match_for_a = Some(page_b);
                            }
                        } else {
                             tracing::warn!("Could not calculate similarity between {} and {}", page_a.metadata.url, page_b.metadata.url);
                        }
                }
            }

                // Use the semantic_threshold for cosine similarity
                // Compare f64 values carefully
                if highest_similarity_for_a >= semantic_threshold {
                if let Some(matched_b) = best_match_for_a {
                        similar_pairs.push(SimilarPagePair {
                        page_a: page_a.metadata.clone(),
                            page_b: matched_b.metadata.clone(),
                            similarity_score: highest_similarity_for_a, // Store the cosine similarity
                    });
                }
            }
            } else {
                 tracing::debug!("Skipping comparison for page_a without embedding: {}", page_a.metadata.url);
        }
        }
    } // End of comparison scope

    tracing::info!("Found {} similar page pairs above threshold {}", similar_pairs.len(), request.similarity_threshold);

    // ---> Calculate and Log Performance Metrics <---
    let total_duration = start_time.elapsed();
    let total_processed_count = processed_a.len() + processed_b.len();
    let avg_time_per_page = if total_processed_count > 0 {
        total_duration.as_secs_f64() / total_processed_count as f64
    } else {
        0.0 // Avoid division by zero if no pages were processed
    };

    tracing::info!(
        total_duration_ms = total_duration.as_millis(),
        total_pages_processed = total_processed_count,
        avg_time_per_page_ms = avg_time_per_page * 1000.0, // Convert seconds to milliseconds
        "Similarity comparison complete."
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
#[tracing::instrument(skip(request))]
async fn crawl_domains(
    Json(request): Json<CrawlDomainsRequest>
) -> impl IntoResponse {
    if request.domains.is_empty() {
        return (StatusCode::UNPROCESSABLE_ENTITY, Json(Vec::<CrawlDomainsResponse>::new())).into_response();
    }

    let crawl_futures = request.domains.iter().map(|domain| {
        crawl_single_domain(domain, request.max_pages)
    });
    
    let crawl_span = tracing::info_span!("crawl_all_requested_domains");
    let results = join_all(crawl_futures).instrument(crawl_span).await;
    
    (StatusCode::OK, Json(results)).into_response()
}

#[tracing::instrument(skip(domain), fields(domain = %domain, max_pages = %max_pages))]
async fn crawl_single_domain(domain: &str, max_pages: usize) -> CrawlDomainsResponse {
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