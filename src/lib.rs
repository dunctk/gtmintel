use axum::{
    extract::Query,
    routing::get,
    Router,
    Json,
};
use serde::{Deserialize, Serialize};
use tower_http::cors::{CorsLayer, Any};
use utoipa::{OpenApi, ToSchema, IntoParams};
use utoipa_swagger_ui::SwaggerUi;

#[derive(Debug, Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ResearchQuery {
    /// Domain name to analyze
    domain: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ResearchResponse {
    /// Domain that was analyzed
    domain: String,
    /// Number of new pages found in the last 7 days
    new_pages_last_7_days: i32,
}

#[derive(OpenApi)]
#[openapi(
    paths(research_pages),
    components(schemas(ResearchQuery, ResearchResponse))
)]
struct ApiDoc;

/// Get the number of new pages published in the last 7 days for a given domain
#[utoipa::path(
    get,
    path = "/research/pages",
    params(ResearchQuery),
    responses(
        (status = 200, description = "Successfully retrieved page count", body = ResearchResponse)
    )
)]
async fn research_pages(Query(query): Query<ResearchQuery>) -> Json<ResearchResponse> {
    // Mock implementation - returns random number between 0 and 100
    let response = ResearchResponse {
        domain: query.domain,
        new_pages_last_7_days: 42, // Mocked value
    };
    Json(response)
}

/// Create the application with all routes and middleware
pub fn create_app() -> Router {
    // Build our API documentation
    let api_doc = ApiDoc::openapi();

    // Create our router
    Router::new()
        .route("/research/pages", get(research_pages))
        .merge(SwaggerUi::new("/docs").url("/api-doc/openapi.json", api_doc))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
} 