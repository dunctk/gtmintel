use std::env;
use reqwest::Client;
use sea_orm::prelude::*;
use sea_orm::{DatabaseConnection, ActiveModelTrait, Set};
use serde_json::Value as Json; // Alias for clarity
use std::time::Duration as StdDuration;
use tracing::{info, warn, error, debug};
use dotenv::dotenv;

// Import the entity and the helper struct for deserialization
use crate::entities::hiring_ads::{self as hiring_ads_entity, JobListing};

// List of substrings that, if found in a company website URL, will cause the job ad to be skipped.
const FORBIDDEN_WEBSITE_SUBSTRINGS: &[&str] = &[
    "workday",
    "bit.ly",
    // Add more forbidden substrings here in the future
];

/// Fetches job listings from Apify, performs basic processing, and saves to the database.
pub async fn run_industry_hiring_ads(
    conn: Option<&DatabaseConnection>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    dotenv().ok(); // Load .env file if present

    let api_url = env::var("APIFY_SCRAPER_RESULT_URL")
        .map_err(|_| "APIFY_SCRAPER_RESULT_URL must be set in .env or environment")?;

    if api_url.is_empty() {
        return Err("APIFY_SCRAPER_RESULT_URL cannot be empty".into());
    }

    info!("Fetching job listings from: {}", api_url);

    let client = Client::builder()
        .timeout(StdDuration::from_secs(60))
        .build()?;

    // --- 1. Fetch data from Apify --- 
    let response = client.get(&api_url).send().await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_else(|_| "Failed to read error body".to_string());
        error!("Apify API error: Status {}, URL: {}, Body: {}", status, api_url, error_text);
        return Err(format!("Apify API request failed with status: {}", status).into());
    }

    let job_listings: Vec<JobListing> = response.json().await
        .map_err(|e| {
            error!("Failed to parse JSON response: {}", e);
            format!("Failed to parse JSON response: {}", e)
        })?;

    info!("Fetched {} job listings from Apify.", job_listings.len());

    let db = match conn {
        Some(db_conn) => db_conn,
        None => {
            warn!("No database connection provided. Job listings will only be printed.");
            // Optionally, proceed without DB operations if desired for testing
            // return Ok(()); // Or exit early if DB is mandatory
            // For now, let's just print and skip DB ops if no connection
            for job in job_listings {
                println!("Job Ad (no DB): {} @ {}", job.title, job.company_name);
            }
            return Ok(());
        }
    };

    let mut inserted_count = 0;
    let mut skipped_count = 0;
    let mut error_count = 0;

    // --- 2. Process and Save Listings --- 
    'job_loop: for job in job_listings {
        debug!("Processing job: {} @ {}", job.title, job.company_name);

        // --- Filtering Logic ---
        // 1. Exclude companies with more than 150 employees
        if let Some(count) = job.company_employees_count {
            if count > 150 {
                debug!("Skipping job ({} @ {}): Company employees ({}) > 150", job.title, job.company_name, count);
                skipped_count += 1;
                continue 'job_loop;
            }
        }

        // 2. Exclude jobs without a company website or with specific keywords
        match &job.company_website {
            None => {
                debug!("Skipping job ({} @ {}): Missing company website", job.title, job.company_name);
                skipped_count += 1;
                continue 'job_loop;
            }
            Some(website) => {
                let website_lower = website.to_lowercase();
                // Check against the list of forbidden substrings
                for forbidden in FORBIDDEN_WEBSITE_SUBSTRINGS {
                    if website_lower.contains(forbidden) {
                        debug!(
                            "Skipping job ({} @ {}): Website contains forbidden substring '{}' ({})",
                            job.title, job.company_name, forbidden, website
                        );
                        skipped_count += 1;
                        continue 'job_loop; // Use labeled loop to break outer loop iteration
                    }
                }
            }
        }
        // --- End Filtering Logic ---

        // --- Placeholder for Enrichment/Filtering --- 
        // TODO: Implement enrichment logic (e.g., categorize seniority, parse salary)
        let is_relevant_placeholder = Some(true); // Example: assume relevant for now
        let enrichment_data_placeholder: Option<Json> = None; // Example: no extra data yet
        // --- End Placeholder --- 

        // Parse postedAt date string (YYYY-MM-DD) into NaiveDate
        let posted_at_date = match job.posted_at {
            Some(ref date_str) => {
                match chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
                    Ok(date) => Some(date),
                    Err(e) => {
                        warn!("Failed to parse date '{}' for job {}: {}. Skipping date.", date_str, job.id, e);
                        None
                    }
                }
            }
            None => None,
        };

        let am = hiring_ads_entity::ActiveModel {
            linkedin_id: Set(job.id.clone()), // Use the JSON 'id' field
            tracking_id: Set(job.tracking_id),
            ref_id: Set(job.ref_id),
            link: Set(job.link),
            title: Set(job.title),
            company_name: Set(job.company_name),
            company_linkedin_url: Set(job.company_linkedin_url),
            company_logo: Set(job.company_logo),
            location: Set(job.location),
            salary_info: Set(job.salary_info),
            posted_at: Set(posted_at_date),
            benefits: Set(job.benefits),
            description_html: Set(job.description_html),
            applicants_count: Set(job.applicants_count),
            apply_url: Set(job.apply_url),
            description_text: Set(job.description_text),
            seniority_level: Set(job.seniority_level),
            employment_type: Set(job.employment_type),
            job_function: Set(job.job_function),
            industries: Set(job.industries),
            input_url: Set(job.input_url),
            company_description: Set(job.company_description),
            company_address: Set(job.company_address),
            company_website: Set(job.company_website),
            company_slogan: Set(job.company_slogan),
            company_employees_count: Set(job.company_employees_count),
            is_relevant: Set(is_relevant_placeholder),
            enrichment_data: Set(enrichment_data_placeholder),
            // created_at and updated_at will be set by the database default/on_update triggers
            ..Default::default() // Use default for id, created_at, updated_at
        };

        match am.insert(db).await {
            Ok(_) => {
                debug!("Successfully inserted job with linkedin_id: {}", job.id);
                inserted_count += 1;
            }
            Err(e) => {
                let msg = e.to_string().to_lowercase();
                // Check for unique constraint violation on linkedin_id
                if msg.contains("unique constraint") || msg.contains("duplicate key value violates unique constraint") {
                    warn!("Skipping duplicate job (linkedin_id: {}): {}", job.id, e);
                    skipped_count += 1;
                } else {
                    error!("DB insert failed for job (linkedin_id: {}): {}", job.id, e);
                    error_count += 1;
                }
            }
        }
    }

    info!("Finished processing job ads. Inserted: {}, Skipped (duplicates): {}, Errors: {}",
           inserted_count, skipped_count, error_count);

    Ok(())
}

// Example main function for standalone execution (similar to industry_funding.rs)
// You might integrate run_industry_hiring_ads into a larger scheduler or application entry point.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Setup tracing/logging
    tracing_subscriber::fmt::init();

    dotenv().ok(); // Load .env file

    // --- Database Connection Setup (replace with your actual setup) ---
    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let conn = match sea_orm::Database::connect(&db_url).await {
        Ok(db) => {
            info!("Database connection established.");
            Some(db)
        }
        Err(e) => {
            error!("Failed to connect to database: {}. Cannot run job.", e);
            // Explicitly cast the Box<DbErr> to the trait object type required by the function signature
            return Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>);
        }
    };
    // --- End Database Connection Setup ---

    // Run the job, passing the connection reference
    if let Err(e) = run_industry_hiring_ads(conn.as_ref()).await {
        error!("Industry hiring ads job execution failed: {}", e);
        return Err(e);
    }

    info!("Industry hiring ads job completed successfully.");
    Ok(())
}
