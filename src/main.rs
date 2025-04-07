use marketintel_api::create_app;
use tracing_subscriber;

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Run our server
    let app = create_app();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    tracing::info!("Server running on http://127.0.0.1:3000");
    axum::serve(listener, app).await.unwrap();
}
