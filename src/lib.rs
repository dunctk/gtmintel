use axum::{
    extract::Query,
    routing::get,
    Router,
    Json,
    response::IntoResponse,
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use tower_http::cors::{CorsLayer, Any};
use utoipa::{OpenApi, ToSchema, IntoParams};
use utoipa_swagger_ui::SwaggerUi;
use std::error::Error;
use sitemap::reader::{SiteMapReader, SiteMapEntity};
use sitemap::structs::LastMod;
use chrono::{Utc, Duration};
use std::io::Cursor;
use texting_robots::Robot;
use std::collections::{VecDeque, HashSet};
use tower_governor::{
    governor::GovernorConfigBuilder,
    key_extractor::SmartIpKeyExtractor,
    GovernorLayer
};
use std::num::NonZeroU32;
use std::sync::Arc;

#[derive(Debug, Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ResearchQuery {
    /// Domain name to analyze
    domain: String,
    /// Optional: Set to true to include the list of new page URLs in the response. Defaults to false.
    #[serde(default)] // Defaults to false if not present
    #[param(required = false)] // Mark as optional for OpenAPI
    list_pages: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ResearchResponse {
    /// Domain that was analyzed
    domain: String,
    /// Number of pages updated in the last 7 days
    updated_pages_last_7_days: i32,
    /// URL of the sitemap that was analyzed (if found)
    sitemap_url: Option<String>,
    /// Optional: List of URLs for pages updated in the last 7 days (present if list_pages=true)
    #[serde(skip_serializing_if = "Option::is_none")]
    updated_page_urls: Option<Vec<String>>,
}

/// Get the number of pages updated in the last 7 days for a given domain
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

    // Initialize response body with updated field names
    let mut response_body = ResearchResponse {
        domain: query.domain.clone(),
        updated_pages_last_7_days: 0,
        sitemap_url: None,
        updated_page_urls: None,
    };

    let should_list_pages = query.list_pages.unwrap_or(false);

    match sitemap_result {
        Ok(Some(sitemap_url)) => {
            response_body.sitemap_url = Some(sitemap_url.clone());
            match count_recent_pages(&sitemap_url).await {
                Ok((count, urls)) => {
                    response_body.updated_pages_last_7_days = count;
                    if should_list_pages {
                        response_body.updated_page_urls = Some(urls);
                    }
                    tracing::info!("Found {} recently updated pages in sitemap", count);
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

/// Count pages modified in the last 7 days from a sitemap URL, handling sitemap indexes.
/// Returns a tuple: (count, list_of_updated_page_urls).
async fn count_recent_pages(initial_sitemap_url: &str) -> Result<(i32, Vec<String>), Box<dyn Error + Send + Sync>> {
    let mut pages_counted = 0;
    let mut updated_page_urls: Vec<String> = Vec::new();
    let cutoff_date = Utc::now() - Duration::days(7);

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

    tracing::info!("Finished processing. Found {} recently updated pages.", pages_counted);
    // Return both the count and the list of URLs
    Ok((pages_counted, updated_page_urls))
}

#[derive(OpenApi)]
#[openapi(
    paths(research_pages),
    components(schemas(ResearchQuery, ResearchResponse))
)]
struct ApiDoc;

/// Create the application with all routes and middleware
pub fn create_app() -> Router {
    // Build our API documentation
    let api_doc = ApiDoc::openapi();

    // --- Configure Rate Limiting using GovernorConfigBuilder ---
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .period(std::time::Duration::from_secs(12))
            .burst_size(NonZeroU32::new(2).unwrap().into())
            .finish()
            .unwrap(),
    );

    // Create our router
    Router::new()
        .route("/research/pages/updated", get(research_pages))
        // Add more routes here if needed
        .merge(SwaggerUi::new("/docs").url("/api-doc/openapi.json", api_doc))
        // --- Apply layers directly to the Router ---
        .layer(GovernorLayer {
            config: governor_conf,
        })
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
} 