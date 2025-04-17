use accessibility_rs::{audit, AuditConfig, AuditResults};
use accessibility_rs::engine::issue::{Issue, RunnerExtras};
use axum::{
    extract::{Query, State},
    response::IntoResponse,
    Json, http::StatusCode
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use crate::AppState;
use crate::error::AppError;

#[derive(Debug, Deserialize, IntoParams, ToSchema)]
pub struct AccessibilityQuery {
    /// URL to scan for accessibility issues
    url: String,
}

// Define our own accessibility issue structure for serialization
#[derive(Debug, Serialize, ToSchema)]
pub struct AccessibilityIssueExtras {
    /// Help URL for the issue
    help_url: String,
    /// Description of the issue
    description: String,
    /// Impact of the issue
    impact: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AccessibilityIssue {
    /// Element context where the issue was found
    context: String,
    /// CSS selectors for the element
    selectors: Vec<String>,
    /// WCAG code reference
    code: String,
    /// Type of issue (error, warning, etc.)
    issue_type: String,
    /// Type code
    type_code: i32,
    /// Descriptive message about the issue
    message: String,
    /// Tool that found the issue
    runner: String,
    /// Additional information about the issue
    runner_extras: AccessibilityIssueExtras,
    /// How many times this issue occurred
    recurrence: i32,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AccessibilityResponse {
    /// URL originally requested for the scan
    requested_url: String,
    /// Whether the overall scan process initiated successfully
    success: bool,
    /// Total number of issues found across all scanned pages
    total_issue_count: usize,
    /// Map where keys are the actual URLs scanned (including sub-pages if crawled)
    /// and values are the list of issues found for that specific URL.
    results_by_url: std::collections::HashMap<String, Vec<AccessibilityIssue>>,
}

/// Endpoint for scanning websites for accessibility issues
#[utoipa::path(
    get,
    path = "/research/accessibility",
    params(AccessibilityQuery),
    responses(
        (status = 200, description = "Success, audit complete, results grouped by URL", body = AccessibilityResponse),
        (status = 500, description = "Internal Server Error during processing")
    ),
    description = "Scans a website (potentially multiple pages if crawled) for accessibility issues following WCAG guidelines. Results are grouped by the URL where issues were found. This is an authenticated endpoint."
)]
pub async fn scan_accessibility(
    Query(query): Query<AccessibilityQuery>,
    State(_state): State<AppState>
) -> impl IntoResponse {
    // Create accessibility config
    let mut config = AuditConfig::default();
    config.url          = query.url.clone();
    config.bounding_box = true;

    // Call audit directly - it returns AuditResults enum
    let audit_results_enum = audit(&config).await;

    // Print the output for debugging
    println!("Accessibility audit enum for {}: {:?}", query.url, audit_results_enum);

    // Process the AuditResults enum
    let (success, results_map) = match audit_results_enum {
        AuditResults::Page(page_data) => {
            let mut extracted_results: std::collections::HashMap<String, Vec<AccessibilityIssue>> = std::collections::HashMap::new();

            println!("[DEBUG] Processing page_data map. Number of URLs found: {}", page_data.len());

            // Iterate directly over the HashMap from the audit result
            for (url_key, page_issues) in page_data.iter() {
                println!("[DEBUG] Processing issues for URL: {}", url_key);
                let mut issues_for_this_url: Vec<AccessibilityIssue> = Vec::new();

                for issue in page_issues {
                    issues_for_this_url.push(AccessibilityIssue {
                        context: issue.context.clone(),
                        selectors: issue.selectors.clone(),
                        code: issue.code.clone(),
                        issue_type: issue.issue_type.to_string(),
                        type_code: issue.type_code as i32,
                        message: issue.message.clone(),
                        runner: issue.runner.to_string(),
                        runner_extras: AccessibilityIssueExtras {
                            help_url: issue.runner_extras.help_url.to_string(),
                            description: issue.runner_extras.description.to_string(),
                            impact: issue.runner_extras.impact.to_string(),
                        },
                        recurrence: issue.recurrence as i32,
                    });
                }
                 println!("[DEBUG] Finished processing issues for URL: {}. Found {} issues.", url_key, issues_for_this_url.len());
                // Insert the converted issues into our response map, keyed by URL
                extracted_results.insert(url_key.clone(), issues_for_this_url);
            }
            println!("[DEBUG] Finished processing all URLs. Final map size: {}", extracted_results.len());
            (true, extracted_results) // Return success and the map
        },
         // Handle other potential variants
         _ => {
             eprintln!("Audit returned an unexpected variant for {}: {:?}", query.url, audit_results_enum);
             // Return success=false and an empty map
             (false, std::collections::HashMap::new())
         }
    };

    // Calculate total issue count from the map values
    let total_issues = results_map.values().map(|v| v.len()).sum();

    // Create our response
    let response = AccessibilityResponse {
        requested_url: query.url, // The URL the user initially requested
        success,
        total_issue_count: total_issues,
        results_by_url: results_map, // The map containing issues grouped by URL
    };

    // Return the response as JSON
    (StatusCode::OK, Json(response))
}