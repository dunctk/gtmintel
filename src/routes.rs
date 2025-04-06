use axum::{routing::get, Router};
use askama::Template;
use askama_axum::IntoResponse;
use tower_http::services::ServeDir;

// Template Structs (can stay here or move to components.rs/models.rs)
#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {}

#[derive(Template)]
#[template(path = "widget.html")]
struct WidgetTemplate {
    message: String,
}

// Function to create the main application router
pub fn create_router() -> Router {
    Router::new()
        // Serve static files from the `static` directory
        .nest_service("/static", ServeDir::new("static"))
        // Application routes
        .route("/", get(root_handler_askama))
        .route("/load-widget", get(load_widget_handler))
}


// Handlers
async fn root_handler_askama() -> impl IntoResponse {
    let template = IndexTemplate {};
    template
}

async fn load_widget_handler() -> impl IntoResponse {
    let template = WidgetTemplate {
        message: "Content loaded via HTMX!".to_string(),
    };
    template
} 