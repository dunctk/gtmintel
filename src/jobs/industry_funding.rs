// gdelt_fetch.rs – pull the latest 15‑minute GDELT GKG slice and print **early‑stage funding rounds** (seed, Series A, etc.)
// -----------------------------------------------------------------------------
// Cargo.toml – add / ensure these deps
// tokio   = { version = "1.38", features = ["full"] }
// reqwest = { version = "0.12", features = ["rustls-tls"] }
// csv     = "1.3"
// zip     = { version = "0.6", default-features = false, features = ["deflate"] }
// chrono  = { version = "0.4", features = ["std", "clock"] }
// regex   = "1.10"
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

        let v2themes = fields.get(8).unwrap_or(&" ");
        let extras = fields.get(26).unwrap_or(&" "); // Extras column often has amounts
        let headline = fields.get(4).unwrap_or(&" ");

        // Quickly drop records containing any skip phrases
        let themes_lower = v2themes.to_lowercase();
        let head_lower = headline.to_lowercase();
        if LATE_STAGE_SKIP_PHRASES.iter().any(|&p| themes_lower.contains(p))
            || LATE_STAGE_SKIP_PHRASES.iter().any(|&p| head_lower.contains(p))
        {
            continue;
        }

        // 1) Must look like a funding event (theme or regex)
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

        // Extract amount snippet for display (first match)
        let amt_snip = funding_re
            .find(extras)
            .or_else(|| funding_re.find(headline))
            .map(|m| m.as_str())
            .unwrap_or("n/a");

        let ts = fields.get(1).unwrap_or(&" ");
        let source = fields.get(3).unwrap_or(&"<src>");
        let url = fields.get(4).unwrap_or(&"<url>");
        let stage = if early_flag_word {
            stage_re
                .find(headline)
                .or_else(|| stage_re.find(v2themes))
                .map(|m| m.as_str())
                .unwrap_or("early")
        } else {
            "early"
        };

        println!("{ts} | {source} | {amt_snip} | {stage} | {url}");

        // ---- Fetch and process article content ----
        let article_content = match Url::parse(url) {
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
                                            tracing::warn!("Readability failed for {}: {}", url, e);
                                            String::new() // Empty string on readability error
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!("Failed to read bytes from {}: {}", url, e);
                                    String::new() // Empty string on byte read error
                                }
                            }
                        } else {
                            tracing::warn!("HTTP error {} fetching article: {}", resp.status(), url);
                            String::new() // Empty string on non-2xx status
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to fetch article {}: {}", url, e);
                        String::new() // Empty string on network error
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to parse URL {}: {}", url, e);
                String::new() // Empty string on URL parse error
            }
        };
        // ---- End fetch and process ----

        if let Some(db) = conn {
            let am = funding::ActiveModel {
                // id left unset ⇒ auto_increment
                ts:         Set(ts.to_string()),
                source:     Set(source.to_string()),
                amount_text:Set(amt_snip.to_owned()),
                stage:      Set(stage.to_owned()),
                news_url:   Set(url.to_string()),
                article_content: Set(article_content),
                created_at: Set(Utc::now()),
                ..Default::default()
            };

            match am.insert(db).await {
                Ok(_) => {}
                Err(e) => {
                    let msg = e.to_string().to_lowercase();
                    if msg.contains("unique") || msg.contains("duplicate") {
                        tracing::warn!("Skipping duplicate news_url entry: {}", url);
                    } else {
                        tracing::error!("insert failed: {}", e);
                    }
                }
            }
        }

        hits += 1;
        if hits == 40 {
            println!("…truncated after 40 early‑stage hits…");
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
    let args: Vec<String> = env::args().collect();
    let days_back: i64 = args.get(1).and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
    run_industry_funding(None, days_back).await
}
