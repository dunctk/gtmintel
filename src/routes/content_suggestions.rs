use axum::{
    extract::Query,
    http::StatusCode,
    response::IntoResponse,
    extract::State,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;
use reqwest_middleware::ClientWithMiddleware;
use crate::error::AppError;
use crate::AppState;
use crate::WebhookRequest;
use crate::WithWebhook;
use crate::WebhookAcceptedResponse;

/// Request parameters for content improvement suggestions
#[derive(Deserialize, ToSchema)]
pub struct ContentSuggestionsQuery {
    /// URL of the page to analyze
    url: String,
    /// Optional webhook URL to send the result to when the job is complete
    #[serde(default)]
    webhook_url: Option<String>,
    /// Optional flag to control whether to send results to the webhook (default: true)
    #[serde(default = "crate::default_send_results")]
    send_results: bool,
}

/// Response containing content improvement suggestions and corrections
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct SuggestionResponse {
    /// List of content improvement suggestions
    pub suggestions: Vec<Suggestion>,
    /// List of text corrections
    pub corrections: Vec<Correction>,
}

/// Single content improvement suggestion
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, ToSchema)]
pub struct Suggestion {
    /// Topic or subject of the suggestion
    pub topic: String,
    /// Detailed description of the suggestion
    pub description: String,
    /// Relevance score or category ("high", "medium", "low")
    pub relevance: String,
    /// Reference sources for the suggestion
    pub sources: Vec<String>,
}

/// Text correction suggestion
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, ToSchema)]
pub struct Correction {
    /// Original text that needs correction
    pub original_text: String,
    /// Suggested corrected text
    pub corrected_text: String,
    /// Explanation of why the correction is needed
    pub explanation: String,
    /// Reference sources for the correction
    pub sources: Vec<String>,
}

/// Generate content improvement suggestions for a URL
///
/// This endpoint analyzes the content at the provided URL and returns
/// suggestions for improvements and possible corrections.
#[utoipa::path(
    get,
    path = "/research/content-suggestions",
    tag = "Content Research",
    params(
        ("url" = String, Query, description = "URL of the page to analyze"),
        ("webhook_url" = Option<String>, Query, description = "Optional webhook URL to send the result to when the job is complete"),
        ("send_results" = bool, Query, description = "Optional flag to control whether to send results to the webhook (default: true)")
    ),
    responses(
        (status = 200, description = "Content suggestions generated successfully", body = SuggestionResponse),
        (status = 202, description = "Request accepted for processing via webhook", body = WebhookAcceptedResponse),
        (status = 400, description = "Invalid request parameters"),
        (status = 422, description = "Could not process the content at the URL"),
        (status = 500, description = "Internal server error")
    )
)]
#[tracing::instrument(skip(query, state), fields(url = %query.url))]
pub async fn get_content_suggestions(
    Query(query): Query<ContentSuggestionsQuery>,
    State(state): State<AppState>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    // Check if webhook is requested
    if let Some(webhook_url) = query.webhook_url() {
        // Create a job ID
        let job_id = crate::generate_job_id(&state.job_id_counter);
        
        // Set up webhook response
        let webhook_response = WebhookAcceptedResponse {
            job_id: job_id.clone(),
            status: "accepted".to_string(),
        };
        
        // Clone data needed for the async task
        let url = query.url.clone();
        let send_results = query.send_results();
        let webhook_url = webhook_url.clone();
        let client = state.http_client.clone();
        
        // Spawn a task to process the request asynchronously
        tokio::spawn(async move {
            // Process the content suggestions (mocked for now)
            let result = mock_content_suggestions(&url);
            
            // Attempt to send the result to the webhook
            if let Err(e) = crate::send_to_webhook(
                &webhook_url,
                &job_id,
                send_results,
                result,
                &client,
            ).await {
                tracing::error!("Failed to send webhook: {}", e);
            }
        });
        
        // Return accepted response immediately
        return Ok((StatusCode::ACCEPTED, Json(serde_json::json!(webhook_response))));
    }
    
    // For synchronous requests (no webhook)
    // Log the request
    tracing::info!("Generating content suggestions for URL: {}", &query.url);
    
    // Mock response - in a real implementation, this would analyze the actual page content
    let response = mock_content_suggestions(&query.url);
    
    Ok((StatusCode::OK, Json(serde_json::json!(response))))
}

/// Creates a mock suggestion response for testing
fn mock_content_suggestions(url: &str) -> SuggestionResponse {
    // Generate some mock suggestions based on the URL
    let domain = url.split('/').nth(2).unwrap_or("example.com");
    
    SuggestionResponse {
        suggestions: vec![
            Suggestion {
                topic: "SEO Optimization".to_string(),
                description: format!("Add more structured data to improve search visibility for {}.", domain),
                relevance: "high".to_string(),
                sources: vec![
                    "https://developers.google.com/search/docs/guides/intro-structured-data".to_string(),
                ],
            },
            Suggestion {
                topic: "Content Structure".to_string(),
                description: "Break up long paragraphs into smaller, more digestible sections.".to_string(),
                relevance: "medium".to_string(),
                sources: vec![
                    "https://www.nngroup.com/articles/how-users-read-on-the-web/".to_string(),
                ],
            },
            Suggestion {
                topic: "User Engagement".to_string(),
                description: "Add a clear call-to-action at the end of each main section.".to_string(),
                relevance: "high".to_string(),
                sources: vec![
                    "https://unbounce.com/conversion-rate-optimization/call-to-action-examples/".to_string(),
                ],
            },
        ],
        corrections: vec![
            Correction {
                original_text: "Customers often struggle with implementation of our software.".to_string(),
                corrected_text: "Our customers can easily implement our software with our step-by-step guide.".to_string(),
                explanation: "Use positive framing to highlight solutions rather than problems.".to_string(),
                sources: vec![
                    "https://www.nngroup.com/articles/positive-language/".to_string(),
                ],
            },
            Correction {
                original_text: "Contact us for more informations.".to_string(),
                corrected_text: "Contact us for more information.".to_string(),
                explanation: "'Information' is an uncountable noun and should not be pluralized.".to_string(),
                sources: vec![
                    "https://dictionary.cambridge.org/grammar/british-grammar/information-news-advice-and-progress".to_string(),
                ],
            },
        ],
    }
}

// Implement WithWebhook trait for ContentSuggestionsQuery
impl WithWebhook for ContentSuggestionsQuery {
    fn webhook_url(&self) -> Option<&String> {
        self.webhook_url.as_ref()
    }
    
    fn send_results(&self) -> bool {
        self.send_results
    }
} 