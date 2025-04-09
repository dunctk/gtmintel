use axum::{
    extract::Query,
    routing::get,
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
#[cfg(not(test))]
use std::sync::Arc;

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
    paths(
        research_pages,
        health_check
    ),
    components(schemas(ResearchQuery, ResearchResponse))
)]
struct ApiDoc;

/// Create the application with all routes and middleware
pub fn create_app() -> Router {
    // Build our API documentation (needed regardless for ApiDoc::openapi())
    let api_doc = ApiDoc::openapi();

    // --- Define API routes separately ---
    // ✨ ADD ALL NEW API ROUTES HERE ✨
    let api_routes = Router::new()
        .route("/research/pages/updated", get(research_pages))
        .route("/health", get(health_check)); // Decide if /health should be rate-limited too
        // .route("/new/api/endpoint", get(new_handler)) // Example of adding a new route

    // --- Conditionally apply layers and Swagger UI only when NOT running tests ---
    #[cfg(not(test))]
    let (docs_router, rate_limited_api_routes) = {
        // Create Swagger UI router
        let docs_router = SwaggerUi::new("/docs").url("/api-doc/openapi.json", api_doc);

        // Configure Rate Limiting
        let governor_conf = Arc::new(
            GovernorConfigBuilder::default()
                .key_extractor(SmartIpKeyExtractor)
                .period(std::time::Duration::from_secs(12))
                .burst_size(NonZeroU32::new(5).unwrap().into())
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