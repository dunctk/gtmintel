// gdelt_fetch.rs – pull the latest 15‑minute GDELT GKG slice and print **early‑stage funding rounds** (seed, Series A, etc.)
// -----------------------------------------------------------------------------
// Cargo.toml – add / ensure these deps
// tokio   = { version = "1.38", features = ["full"] }
// reqwest = { version = "0.12", features = ["rustls-tls"] }
// csv     = "1.3"
// zip     = { version = "0.6", default-features = false, features = ["deflate"] }
// chrono  = { version = "0.4", features = ["std", "clock"] }
// regex   = "1.10"
// serde   = { version = "1.0", features = ["derive"] }
// serde_json = "1.0"
// -----------------------------------------------------------------------------
// What changed?
// • Removed every reference to IPO (both themes and regex).
// • Added `EARLY_STAGE_RE` that matches *seed*, *pre‑seed*, *angel*, *Series A/B*.
// • Rows must satisfy **both** a funding signal *and* an early‑stage keyword (or the
//   amount is < $50 M by heuristic). Large later‑stage rounds are skipped.
// • Compact summary: <timestamp> | <source> | <amount> | <stage> | <url>

use chrono::{Datelike, Duration, Timelike, Utc};
use csv::ReaderBuilder;
use regex::Regex;
use reqwest::Client;
use std::{io::Cursor, time::Duration as StdDuration};
use zip::ZipArchive;
use std::env;
use sea_orm::{DatabaseConnection, ActiveModelTrait, Set};
use crate::entities::funding;          // ← module we just created
use url::Url;
use llm_readability::extractor;
use reqwest::header;
use serde::{Deserialize, Serialize};
use serde_json::json;

const BASE_URL: &str = "http://data.gdeltproject.org/gdeltv2";

// Theme tags that strongly signal venture / private funding.
const FUNDING_TAGS: &[&str] = &[
    "CAPITAL_MARKET_FUNDRAISING",
    "VENTURE_CAPITAL",
    "CAPITALMARKET_EQUITYFUNDING",
    "CAPITALMARKET_PRIVATEEQUITY",
];

// Regex that spots monetary raise phrasing: "raised $12.5M", "secures €8m", etc.
const FUNDING_REGEX: &str = r"(?i)\b(raise[sd]?|secures?|lands?|closes?)\b[^\$€£]{0,20}[\$€£]\s?[\d,.]+\s*(k|m|bn|billion|million)?";

// Regex for early‑stage cues.
const EARLY_STAGE_REGEX: &str = r"(?i)\b(pre[- ]?seed|seed|angel|series\s+[ab])\b";

// Skip phrases to filter out (case-insensitive)
const LATE_STAGE_SKIP_PHRASES: &[&str] = &[
    "ipo",
    "initial public offering",
    "spac",
    "debt round",
    "land sales",
];

// Add a spoofed User-Agent
const SPOOFED_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36";

#[derive(Deserialize, Debug)]
struct OpenAIResponse {
    output: String,
}

async fn is_truly_early_stage(
    client: &Client,
    article_content: &str,
    news_url: &str,
    headline: &str,
    source: &str,
    endpoint: &str,
    api_key: &str,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    if article_content.is_empty() {
        tracing::debug!("Article content is empty, cannot verify.");
        return Ok(false); // Cannot verify empty content
    }

    // Truncate article content if too long to avoid large request payloads
    let max_len = 8000; // Adjust as needed, consider token limits
    let truncated_content = if article_content.len() > max_len {
        tracing::debug!("Truncating article content from {} to {} chars for OpenAI prompt.", article_content.len(), max_len);
        &article_content[..max_len]
    } else {
        article_content
    };

    let prompt = if !article_content.is_empty() {
        format!(
            "Analyze the following news article content, considering its source URL. Does it definitively describe a seed, pre-seed, or angel funding round? Answer with only 'YES' or 'NO'.\n\nArticle:\n{}\n\nSource URL: {}",
            truncated_content,
            news_url
        )
    } else {
        format!(
            "Primary content extraction failed for the news article linked below (headline and source provided). Based *only* on the URL, headline, source domain, and any information you can access from the URL (e.g., via web search), does this article likely describe a seed, pre-seed, or angel funding round? Answer with only 'YES' or 'NO'.\n\nHeadline: {}\nSource: {}\nURL: {}",
            headline,
            source,
            news_url
        )
    };

    let request_body = json!({
        "model": "gpt-4o", // Or your specific deployment name if not using the base model name
        "input": prompt,
        "tools": [{ "type": "web_search_preview" }],
    });

    // Construct the full URL for the specific API endpoint
    // Ensure the endpoint from env var is just the base resource name like "https://YOUR-RESOURCE-NAME.openai.azure.com"
    let full_url = format!("{}/openai/responses?api-version=2025-03-01-preview", endpoint.trim_end_matches('/'));
    tracing::debug!("Calling OpenAI API: {}", full_url);


    let response = client
        .post(&full_url)
        .header("api-key", api_key)
        .header(header::CONTENT_TYPE, "application/json")
        .timeout(StdDuration::from_secs(90)) // Increased timeout for LLM call
        .json(&request_body)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_else(|_| "Failed to read error body".to_string());
        tracing::error!("OpenAI API error: Status {}, URL: {}, Body: {}", status, full_url, error_text);
        // Consider returning an error or false depending on desired behavior
        return Err(format!("OpenAI API request failed with status: {}", status).into());
    }

    // It's safer to deserialize into a generic Value first if the structure might vary
    // let response_json: serde_json::Value = response.json().await?;
    // tracing::debug!("OpenAI Raw Response: {:?}", response_json);
    // let output = response_json.get("output").and_then(|v| v.as_str()).unwrap_or("");
    // Ok(output.trim().eq_ignore_ascii_case("YES"))

    // Or stick with the struct if confident about the structure:
    match response.json::<OpenAIResponse>().await {
         Ok(response_json) => {
            tracing::debug!("OpenAI Parsed Response: {:?}", response_json);
            Ok(response_json.output.trim().eq_ignore_ascii_case("YES"))
         }
         Err(e) => {
            tracing::error!("Failed to parse OpenAI JSON response: {}", e);
            Err(e.into()) // Propagate JSON parsing error
         }
    }
}

/// Fetch the latest **early‑stage funding** rows from GDELT and print them.
///
/// `days_back` lets callers rewind N days when back‑filling.
pub async fn run_industry_funding(
    conn: Option<&DatabaseConnection>,
    days_back: i64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::builder()
        .timeout(StdDuration::from_secs(60))
        .build()?;

    // —— 1️⃣  Compute last completed 15‑min slice (UTC – 5‑min cushion)
    let now = Utc::now() - Duration::minutes(5) - Duration::days(days_back);
    let rounded_min = now.minute() / 15 * 15;
    let slice_time = now
        .with_second(0)
        .unwrap()
        .with_nanosecond(0)
        .unwrap()
        .with_minute(rounded_min)
        .unwrap();

    let stamp = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}",
        slice_time.year(),
        slice_time.month(),
        slice_time.day(),
        slice_time.hour(),
        slice_time.minute(),
        slice_time.second()
    );

    let url = format!("{BASE_URL}/{stamp}.gkg.csv.zip");
    println!("Fetching {url}\n");

    // —— 2️⃣  Download and unzip
    let bytes = client
        .get(&url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    let reader = Cursor::new(bytes);
    let mut zip = ZipArchive::new(reader)?;
    let mut csv_file = zip.by_index(0)?; // first (only) entry

    let mut csv_reader = ReaderBuilder::new()
        .delimiter(b'\t')
        .has_headers(false)
        .from_reader(&mut csv_file);

    let funding_re = Regex::new(FUNDING_REGEX)?;
    let stage_re = Regex::new(EARLY_STAGE_REGEX)?;

    let mut hits = 0;

    for result in csv_reader.records() {
        let rec = result?;
        let fields: Vec<&str> = rec.iter().collect();

        // Extract necessary fields early on
        let ts = fields.get(1).unwrap_or(&" ");
        let source = fields.get(3).unwrap_or(&"<src>");
        let url_str = fields.get(4).unwrap_or(&"<url>"); // Rename to avoid clash later
        let headline = fields.get(5).unwrap_or(&" "); // GDELT GKG v2 format: headline is field 5
        let v2themes = fields.get(8).unwrap_or(&" ");
        let extras = fields.get(26).unwrap_or(&" "); // Extras column often has amounts

        // --- Filtering Logic ---
        // Quickly drop records containing any skip phrases (in themes or headline)
        let themes_lower = v2themes.to_lowercase();
        let head_lower = headline.to_lowercase();
        if LATE_STAGE_SKIP_PHRASES.iter().any(|&p| themes_lower.contains(p))
            || LATE_STAGE_SKIP_PHRASES.iter().any(|&p| head_lower.contains(p))
        {
            continue;
        }

        // 1) Must look like a funding event (theme or regex in extras/headline)
        let theme_flag = FUNDING_TAGS.iter().any(|tag| v2themes.contains(tag));
        let regex_flag = funding_re.is_match(extras) || funding_re.is_match(headline);
        if !(theme_flag || regex_flag) {
            continue;
        }

        // 2) Early‑stage indicator: seed/Series A words **or** amount < $50 M.
        let early_flag_word = stage_re.is_match(v2themes) || stage_re.is_match(headline);
        let early_flag_amt = amount_under_50m(extras) || amount_under_50m(headline);
        if !(early_flag_word || early_flag_amt) {
            continue; // likely later stage
        }
        // --- End Filtering Logic ---

        // Extract amount snippet for display (first match from extras or headline)
        let amt_snip = funding_re
            .find(extras)
            .or_else(|| funding_re.find(headline))
            .map(|m| m.as_str())
            .unwrap_or("n/a");

        // Determine initial stage guess based on keywords
        let stage = if early_flag_word {
            stage_re
                .find(headline)
                .or_else(|| stage_re.find(v2themes))
                .map(|m| m.as_str())
                .unwrap_or("early") // Default if regex found but no specific stage word
        } else {
            "early" // Default if only amount heuristic matched
        };

        println!("{ts} | {source} | {amt_snip} | {stage} | {url_str}");


        // ---- Fetch and process article content ----
        let article_content = match Url::parse(url_str) {
            Ok(parsed_url) => {
                match client.get(parsed_url.clone()) // Clone parsed_url here
                           .header(header::USER_AGENT, SPOOFED_USER_AGENT)
                           .timeout(StdDuration::from_secs(30)) // Add timeout for article fetch
                           .send()
                           .await {
                    Ok(resp) => {
                        if resp.status().is_success() {
                            match resp.bytes().await {
                                Ok(html_bytes) => {
                                    let mut cursor = Cursor::new(html_bytes);
                                    match extractor::extract(&mut cursor, &parsed_url) { // Use parsed_url here
                                        Ok(product) => {
                                            // Convert readable HTML to Markdown
                                            html2md::rewrite_html(&product.content, false)
                                        }
                                        Err(e) => {
                                            tracing::warn!("Readability failed for {}: {}", url_str, e);
                                            String::new() // Empty string on readability error
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!("Failed to read bytes from {}: {}", url_str, e);
                                    String::new() // Empty string on byte read error
                                }
                            }
                        } else {
                            tracing::warn!("HTTP error {} fetching article: {}", resp.status(), url_str);
                            String::new() // Empty string on non-2xx status
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to fetch article {}: {}", url_str, e);
                        String::new() // Empty string on network error
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to parse URL {}: {}", url_str, e);
                String::new() // Empty string on URL parse error
            }
        };
        // ---- End fetch and process ----

        // ---- Verify with OpenAI (always attempt) ----
        let mut is_confirmed_early = false; // Default to false unless verified
        let mut verification_performed = false; // Track if verification was attempted

        // Read Azure OpenAI credentials from environment variables
        let openai_endpoint = env::var("AZURE_OPENAI_ENDPOINT");
        let openai_api_key = env::var("AZURE_OPENAI_API_KEY");

        match (openai_endpoint, openai_api_key) {
            (Ok(endpoint), Ok(api_key)) => {
                if !endpoint.is_empty() && !api_key.is_empty() {
                     verification_performed = true;
                     // Pass url_str, headline, source along with content
                     match is_truly_early_stage(&client, &article_content, url_str, headline, source, &endpoint, &api_key).await {
                        Ok(confirmed) => {
                            is_confirmed_early = confirmed;
                            if confirmed {
                                println!(">>> OpenAI confirmed early stage for: {}", url_str);
                            } else {
                                if !article_content.is_empty() {
                                     println!(">>> OpenAI did NOT confirm early stage for: {}", url_str);
                                } else {
                                     println!(">>> OpenAI did NOT confirm early stage (based on URL/meta) for: {}", url_str);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("OpenAI verification failed for {}: {}", url_str, e);
                            // Decide behavior on API error: skip or proceed without confirmation?
                            // Defaulting to skip (is_confirmed_early remains false)
                        }
                    }
                } else {
                    tracing::warn!("AZURE_OPENAI_ENDPOINT or AZURE_OPENAI_API_KEY is empty. Skipping OpenAI verification.");
                    // is_confirmed_early remains false
                }
            }
            _ => {
                tracing::warn!("AZURE_OPENAI_ENDPOINT or AZURE_OPENAI_API_KEY not set. Skipping OpenAI verification.");
                // is_confirmed_early remains false
            }
        }
        // ---- End OpenAI verification ----

        // ---- Determine stage_checked value ----
        let stage_checked_value = if is_confirmed_early {
            "seed"
        } else {
            "other" // Includes "NO" from OpenAI, failed checks, skipped checks, empty content
        }.to_string();

        // ---- Insert into DB (always attempt if connection exists) ----
        if let Some(db) = conn {
             let am = funding::ActiveModel {
                    ts: Set(ts.to_string()),
                    source: Set(source.to_string()),
                    amount_text: Set(amt_snip.to_owned()),
                    stage: Set(stage.to_owned()), // Keep original stage guess? Or update?
                    news_url: Set(url_str.to_string()), // Use url_str here
                    article_content: Set(article_content), // Store full content even if truncated for prompt
                    created_at: Set(Utc::now()),
                    stage_checked: Set(stage_checked_value), // Set the new column
                    ..Default::default()
             };

             match am.insert(db).await {
                 Ok(_) => {
                      if is_confirmed_early {
                          println!("   Successfully inserted record (Stage checked: seed).");
                      } else {
                          println!("   Successfully inserted record (Stage checked: other).");
                      }
                         hits += 1; // Increment hits only for confirmed & inserted records
                    }
                    Err(e) => {
                        let msg = e.to_string().to_lowercase();
                        if msg.contains("unique") || msg.contains("duplicate") {
                            tracing::warn!("Skipping duplicate (already inserted?) news_url entry: {}", url_str);
                        } else {
                            tracing::error!("DB insert failed: {}", e);
                        }
                 }
             }
        } else {
             // If no DB connection, just print the determined stage?
             println!("   Determined stage (not saving to DB): {} | URL: {}", stage_checked_value, url_str);
             // Optionally increment hits here if you want to count non-DB confirmed items
             // if is_confirmed_early { hits += 1; }
        }
        // ---- End conditional insert ----

        // Moved hit limit check outside the DB insertion block
        // Check based on CONFIRMED hits now
        if hits == 40 {
            println!("…truncated after 40 confirmed early‑stage hits…");
            break;
        }
    }

    println!("\nEarly‑stage funding rows in this slice: {hits}");
    Ok(())
}

/// Very naive parser: returns true if we see an amount token under $50M.
fn amount_under_50m(text: &str) -> bool {
    let amt_re = Regex::new(r"[\$€£]\s?([\d,.]+)\s*(m|million)?(?i)").unwrap();
    if let Some(caps) = amt_re.captures(text) {
        if let Some(raw) = caps.get(1) {
            let num: f64 = raw.as_str().replace(',', "").parse().unwrap_or(1e9);
            return num < 50.0; // assume millions
        }
    }
    false
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Setup tracing/logging (optional, but helpful for the new logs)
    tracing_subscriber::fmt::init();

    let args: Vec<String> = env::args().collect();
    let days_back: i64 = args.get(1).and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
    run_industry_funding(None, days_back).await
}
