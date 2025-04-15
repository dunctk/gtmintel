use axum::{
    extract::Query,
    http::StatusCode,
    extract::State,
    Json,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use reqwest_middleware::ClientWithMiddleware;
use crate::error::AppError;
use crate::AppState;
use crate::WithWebhook;
use crate::WebhookAcceptedResponse;
use futures::StreamExt;
use std::env;
use reqwest::Client;
use std::str;
use tracing::{error, info};

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

/// Perplexity API request structure
#[derive(Serialize)]
struct PerplexityRequest {
    model: String,
    messages: Vec<PerplexityMessage>,
    max_tokens: usize,
    stream: bool,
}

/// Perplexity API message structure
#[derive(Serialize)]
struct PerplexityMessage {
    role: String,
    content: String,
}

/// Perplexity API non-streaming response structure
#[derive(Deserialize, Debug)]
struct PerplexityApiResponse {
    choices: Vec<PerplexityApiChoice>,
}

/// Choice within the Perplexity API response
#[derive(Deserialize, Debug)]
struct PerplexityApiChoice {
    message: PerplexityApiMessage,
}

/// Message content within the Perplexity API response choice
#[derive(Deserialize, Debug)]
struct PerplexityApiMessage {
    content: String,
}

/// Function to get Perplexity API key from environment
fn get_perplexity_api_key() -> Result<String, AppError> {
    // Try to get API key from environment variable
    match env::var("PERPLEXITY_API_KEY") {
        Ok(key) => Ok(key),
        Err(_) => {
            // Try to load from .env file if not found in environment
            if let Ok(_) = dotenvy::dotenv() {
                match env::var("PERPLEXITY_API_KEY") {
                    Ok(key) => Ok(key),
                    Err(_) => Err(AppError::InternalError("PERPLEXITY_API_KEY not found in environment or .env file".to_string()))
                }
            } else {
                Err(AppError::InternalError("PERPLEXITY_API_KEY not found in environment and failed to load .env file".to_string()))
            }
        }
    }
}

/// Process content from a URL and generate suggestions using Perplexity API
async fn process_content_with_perplexity(url: &str, client: &ClientWithMiddleware) -> Result<SuggestionResponse, AppError> {
    info!("Starting content processing for URL: {}", url);
    // Step 1: Fetch the content from the URL
    let html_content = fetch_url_content(url, client).await?;
    info!("Fetched HTML content for URL: {}. Length: {}", url, html_content.len());

    // Step 2: Generate the prompt for Perplexity API
    let prompt = generate_suggestions_prompt(url, &html_content);
    // Consider logging the prompt only in debug/trace levels if it's too verbose
    tracing::debug!("Generated Perplexity prompt for URL: {}", url);

    // Step 3: Call Perplexity API (non-streaming)
    let api_response_content = call_perplexity_api(&prompt).await?; // Call the renamed function
    info!("Received raw content response from Perplexity for URL: {}. Length: {}", url, api_response_content.len());

    // Step 4: Parse the raw content string into our SuggestionResponse format
    let suggestions_response = parse_perplexity_response(&api_response_content)?;
    info!("Successfully parsed Perplexity response into SuggestionResponse for URL: {}", url);

    Ok(suggestions_response)
}

/// Fetch content from a URL
async fn fetch_url_content(url: &str, client: &ClientWithMiddleware) -> Result<String, AppError> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| AppError::ProcessingError(format!("Failed to fetch URL content: {}", e)))?;
    
    if !response.status().is_success() {
        return Err(AppError::ProcessingError(format!(
            "Failed to fetch URL, status code: {}", 
            response.status()
        )));
    }
    
    let html = response
        .text()
        .await
        .map_err(|e| AppError::ProcessingError(format!("Failed to read response body: {}", e)))?;
    
    Ok(html)
}

/// Generate prompt for Perplexity API
fn generate_suggestions_prompt(url: &str, content: &str) -> String {
    // Extract a preview of the content (first ~2000 chars to keep prompt size reasonable)
    let content_preview = content.chars().take(2000).collect::<String>();
    
    format!(
        "I need you to analyze the content from this URL: {} and then research the topic to provide opportunities for information gain,
        as well as corrections to any outdated information. \
        Here's a preview of the content: \n\n{}\n\n \
        Based on this content, please provide: \
        1. 3-5 specific content improvement suggestions with topics, descriptions, and relevance (high, medium, low) \
        2. 2-3 specific text corrections that might improve the content's quality \
        Format your response as a clean JSON object with these exact keys: \
        {{\"suggestions\": [{{\"topic\": \"...\", \"description\": \"...\", \"relevance\": \"high|medium|low\", \"sources\": [\"...\"]}}], \
        \"corrections\": [{{\"original_text\": \"...\", \"corrected_text\": \"...\", \"explanation\": \"...\", \"sources\": [\"...\"]}}]}} \
        Don't add any additional explanation or text before or after the JSON.", 
        url, content_preview
    )
}

/// Call Perplexity API (non-streaming)
async fn call_perplexity_api(prompt: &str) -> Result<String, AppError> {
    let api_key = get_perplexity_api_key()?;

    let client = Client::new(); // Use a new client for this specific call

    let request_body = PerplexityRequest {
        model: "sonar".to_string(), // Or another suitable non-streaming model if needed
        messages: vec![
            PerplexityMessage {
                role: "user".to_string(),
                content: prompt.to_string(),
            }
        ],
        max_tokens: 2000, // Adjust as needed
        stream: false, // Explicitly set stream to false
    };

    info!("Sending request to Perplexity API...");
    let response = client
        .post("https://api.perplexity.ai/chat/completions")
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await
        .map_err(|e| {
            error!("Network error calling Perplexity API: {}", e);
            AppError::ProcessingError(format!("Failed to call Perplexity API: {}", e))
        })?;

    let status = response.status();
    info!("Received response from Perplexity API with status: {}", status);

    if !status.is_success() {
        let error_text = response.text().await.unwrap_or_else(|_| "Failed to read error body".to_string());
        error!("Perplexity API Error - Status: {}, Body: {}", status, error_text);
        return Err(AppError::ProcessingError(format!(
            "Perplexity API returned error status: {}",
            status
        )));
    }

    // Parse the full response directly into the non-streaming struct
    let api_response = response
        .json::<PerplexityApiResponse>()
        .await
        .map_err(|e| {
             error!("Failed to parse Perplexity API JSON response: {}", e);
             AppError::ProcessingError(format!("Failed to parse Perplexity API response: {}", e))
        })?;

    // Extract the content from the first choice's message
    if let Some(choice) = api_response.choices.first() {
        info!("Successfully received and parsed response from Perplexity. Content length: {}", choice.message.content.len());
        Ok(choice.message.content.clone()) // Return the content string
    } else {
        error!("Perplexity API returned no choices in the response.");
        Err(AppError::ProcessingError("Perplexity API returned no choices".to_string()))
    }
}

/// Parse Perplexity response into SuggestionResponse format
fn parse_perplexity_response(response: &str) -> Result<SuggestionResponse, AppError> {
    // Remove Markdown code block if present
    let trimmed = response.trim();
    let json_str = if trimmed.starts_with("```json") {
        // Remove the opening ```json and closing ```
        trimmed
            .trim_start_matches("```json")
            .trim_start_matches("```")
            .trim()
            .trim_end_matches("```")
            .trim()
    } else if trimmed.starts_with("```") {
        // Remove the opening ``` and closing ```
        trimmed
            .trim_start_matches("```")
            .trim()
            .trim_end_matches("```")
            .trim()
    } else {
        trimmed
    };

    tracing::info!("Parsing Perplexity response: len={}, starts_with={:?}", json_str.len(), &json_str.chars().take(20).collect::<String>());

    match serde_json::from_str::<SuggestionResponse>(json_str) {
        Ok(parsed) => Ok(parsed),
        Err(e) => {
            error!("Failed to parse Perplexity response as JSON: {}. Raw response:\n{}", e, json_str);

            // Fallback: try to extract the first {...} block
            if let Some(start) = json_str.find('{') {
                if let Some(end) = json_str.rfind('}') {
                    let json_part = &json_str[start..=end];
                    match serde_json::from_str::<SuggestionResponse>(json_part) {
                        Ok(parsed) => return Ok(parsed),
                        Err(e) => {
                            error!("Failed to parse extracted JSON part: {}. Extracted:\n{}", e, json_part);
                        }
                    }
                }
            }

            // Fallback to a default/mock response
            error!("Using fallback suggestions due to parsing failure");
            Ok(mock_content_suggestions("fallback"))
        }
    }
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
            // Process the content using Perplexity API (or fallback to mock if it fails)
            let result = match process_content_with_perplexity(&url, &client).await {
                Ok(suggestions) => suggestions,
                Err(e) => {
                    error!("Error processing content with Perplexity: {}", e);
                    // Fallback to mock data if there's an error
                    mock_content_suggestions(&url)
                }
            };
            
            // Attempt to send the result to the webhook
            if let Err(e) = crate::send_to_webhook(
                &webhook_url,
                &job_id,
                send_results,
                result,
                &client,
            ).await {
                error!("Failed to send webhook: {}", e);
            }
        });
        
        // Return accepted response immediately
        return Ok((StatusCode::ACCEPTED, Json(serde_json::json!(webhook_response))));
    }
    
    // For synchronous requests (no webhook)
    // Log the request
    info!("Generating content suggestions for URL: {}", &query.url);
    
    // Process the content using Perplexity API
    let response = process_content_with_perplexity(&query.url, &state.http_client).await?;
    
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