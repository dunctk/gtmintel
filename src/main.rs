use gtmintel::create_app;
use std::net::SocketAddr;
use tracing_subscriber;
use tracing::Level;

#[tokio::main]
async fn main() {
    // Initialize tracing subscriber with level configuration
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();

    // Run our server
    let app = create_app();
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    tracing::info!("Server running on http://0.0.0.0:3000");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
