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
    /// URL that was scanned
    url: String,
    /// Whether the scan completed successfully
    success: bool,
    /// Number of issues found
    issue_count: usize,
    /// List of accessibility issues found
    issues: Vec<AccessibilityIssue>,
}

/// Endpoint for scanning websites for accessibility issues
#[utoipa::path(
    get,
    path = "/research/accessibility",
    params(AccessibilityQuery),
    responses(
        (status = 200, description = "Success, audit complete", body = AccessibilityResponse),
        (status = 500, description = "Internal Server Error during processing")
    ),
    description = "Scans a website for accessibility issues following WCAG guidelines. This is an authenticated endpoint."
)]
pub async fn scan_accessibility(
    Query(query): Query<AccessibilityQuery>,
    State(_state): State<AppState>
) -> impl IntoResponse {
    // Create accessibility config
    let mut config = AuditConfig::default();
    config.url = query.url.clone();

    // Call audit directly - it returns AuditResults enum
    let audit_results_enum = audit(&config).await;

    // Print the output for debugging
    println!("Accessibility audit enum for {}: {:?}", query.url, audit_results_enum);

    // Process the AuditResults enum
    let (success, issues) = match audit_results_enum {
        // Match the Page variant which contains the HashMap
        AuditResults::Page(page_data) => {
            let mut extracted_issues: Vec<AccessibilityIssue> = Vec::new();
            // Iterate directly over the HashMap
            for (_url_key, page_issues) in page_data.iter() {
                for issue in page_issues {
                    extracted_issues.push(AccessibilityIssue {
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
            }
            (true, extracted_issues) // Return success and the issues
        },
        // Handle other potential variants if they exist
        // Add more match arms here if needed based on the AuditResults definition
         _ => {
             eprintln!("Audit returned an unexpected variant for {}: {:?}", query.url, audit_results_enum);
             (false, Vec::new()) // Indicate failure, return empty issues
         }
    };

    // Create our response
    let response = AccessibilityResponse {
        url: query.url,
        success,
        issue_count: issues.len(),
        issues,
    };

    // Return the response as JSON
    (StatusCode::OK, Json(response))
}