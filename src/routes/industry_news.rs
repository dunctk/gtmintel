#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Vertical {
    Ai,
    Fintech,
    Biotech,
    Healthtech,
    Robotics,
    Other(String), // fallback if needed
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Feed {
    name: String,
    description: String,
    rss: String,
    vertical: Vertical,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct NewsItem {
    /// Title of the news item
    pub title: String,
    /// URL to the full article
    pub link: String,
    /// Publication date in RFC2822 format
    pub published: String,
    /// Optional description or excerpt of the article
    pub description: Option<String>,
    /// Name of the source publication
    pub source: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct NewsResponse {
    /// List of news items
    pub items: Vec<NewsItem>,
    /// Number of days the news items span
    pub days: u32,
}

pub fn load_feeds() -> Result<Vec<Feed>, std::io::Error> {
    let file = std::fs::File::open("/app/data/feeds_ai.json")?;
    let feeds: Vec<Feed> = serde_json::from_reader(file)?;
    Ok(feeds)
}

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use http_cache_reqwest::{Cache, CacheMode, HttpCache, HttpCacheOptions, CACacheManager};
use reqwest::Client;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use rss::Channel;
use chrono::{DateTime, Utc, Duration};
use serde::Deserialize;
use std::error::Error;
use utoipa::{ToSchema, IntoParams};
use crate::AppState;

#[derive(Debug, Deserialize, ToSchema, IntoParams)]
pub struct NewsQuery {
    /// Number of days to look back for news items (default: 7)
    #[serde(default = "default_days")]
    days: u32,
    /// Industry vertical to fetch news for (default: ai)
    #[serde(default = "default_vertical")]
    vertical: String,
}

fn default_days() -> u32 {
    7
}

fn default_vertical() -> String {
    "ai".to_string()
}

/// Retrieve recent industry news from AI-related RSS feeds
#[utoipa::path(
    get,
    path = "/industry/news",
    params(NewsQuery),
    responses(
        (status = 200, description = "Successfully retrieved news items", body = NewsResponse),
        (status = 500, description = "Failed to fetch news", body = NewsResponse)
    ),
    description = "Fetches recent industry news from various AI-related sources. News items are filtered by date and sorted with newest first."
)]
pub async fn fetch_industry_news(
    Query(query): Query<NewsQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match get_news_from_feeds(query.days, query.vertical, state.http_client).await {
        Ok(items) => (
            StatusCode::OK,
            Json(NewsResponse {
                items,
                days: query.days,
            }),
        ),
        Err(e) => {
            eprintln!("Error fetching news feeds: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(NewsResponse {
                    items: vec![],
                    days: query.days,
                }),
            )
        },
    }
}

async fn get_news_from_feeds(days: u32, vertical: String, client: ClientWithMiddleware) -> Result<Vec<NewsItem>, Box<dyn Error + Send + Sync>> {
    let all_feeds = load_feeds().map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
    let cutoff_date = Utc::now() - Duration::days(days as i64);
    
    // Filter feeds by the requested vertical (case-insensitive comparison)
    let vertical_lower = vertical.to_lowercase();
    let filtered_feeds: Vec<&Feed> = all_feeds.iter().filter(|feed| {
        match &feed.vertical {
            Vertical::Ai => vertical_lower == "ai",
            Vertical::Fintech => vertical_lower == "fintech",
            Vertical::Biotech => vertical_lower == "biotech",
            Vertical::Healthtech => vertical_lower == "healthtech",
            Vertical::Robotics => vertical_lower == "robotics",
            Vertical::Other(s) => vertical_lower == s.to_lowercase(),
        }
    }).collect();

    if filtered_feeds.is_empty() {
        eprintln!("No feeds found for vertical: {}", vertical);
        return Ok(Vec::new()); // Return empty list if no feeds match
    }
    
    let mut all_items = Vec::new();
    
    // Iterate over the *filtered* feeds
    for feed in filtered_feeds {
        match fetch_and_parse_feed(&feed, &client).await {
            Ok(mut items) => {
                // Filter items by date
                items.retain(|item| {
                    // Attempt to parse the date
                    if let Ok(date) = DateTime::parse_from_rfc2822(&item.published).or_else(|_| DateTime::parse_from_rfc3339(&item.published)) {
                        date.with_timezone(&Utc) >= cutoff_date
                    } else {
                        eprintln!("Could not parse date: {} for feed {}", item.published, feed.name);
                        false // Skip items with unparseable dates
                    }
                });
                
                all_items.extend(items);
            }
            Err(e) => {
                eprintln!("Error fetching feed {}: {}", feed.name, e);
                // Continue with other feeds
            }
        }
    }
    
    // Sort by published date, newest first
    all_items.sort_by(|a, b| {
        let date_a = DateTime::parse_from_rfc2822(&a.published).or_else(|_| DateTime::parse_from_rfc3339(&a.published)).unwrap_or_default();
        let date_b = DateTime::parse_from_rfc2822(&b.published).or_else(|_| DateTime::parse_from_rfc3339(&b.published)).unwrap_or_default();
        date_b.cmp(&date_a)
    });
    
    Ok(all_items)
}

async fn fetch_and_parse_feed(feed: &Feed, client: &ClientWithMiddleware) -> Result<Vec<NewsItem>, Box<dyn Error + Send + Sync>> {
    let response = client.get(&feed.rss).send().await?;
    let content = response.bytes().await?;
    
    let channel = Channel::read_from(&content[..])?;
    
    let items = channel.items().iter().map(|item| {
        NewsItem {
            title: item.title().unwrap_or("Untitled").to_string(),
            link: item.link().unwrap_or("").to_string(),
            published: item.pub_date().unwrap_or("").to_string(),
            description: item.description().map(|s| s.to_string()),
            source: feed.name.clone(),
        }
    }).collect();
    
    Ok(items)
}

// Helper function to create a cached HTTP client
pub fn create_cached_client() -> ClientWithMiddleware {
    let client = Client::new();
    
    ClientBuilder::new(client)
        .with(Cache(HttpCache {
            mode: CacheMode::Default,
            manager: CACacheManager::default(),
            options: HttpCacheOptions::default(),
        }))
        .build()
}

