use gtmintel::create_app;
use std::net::SocketAddr;
use tracing_subscriber;
use tracing::Level;

// Re-export these functions to lib.rs for easier testing
pub mod server_utils {
    use super::*;
    
    // Extracted function to set up tracing for easier testing
    pub fn setup_tracing() {
        tracing_subscriber::fmt()
            .with_max_level(Level::INFO)
            .init();
    }

    // Extracted function to create and bind the server
    pub async fn setup_server(bind_address: &str) -> (
        tokio::net::TcpListener,
        axum::Router
    ) {
        // Create the app
        let app = create_app();
        
        // Bind to the provided address
        let listener = tokio::net::TcpListener::bind(bind_address).await.unwrap();
        tracing::info!("Server running on http://{}", bind_address);
        
        (listener, app)
    }
}

// Use server_utils internally
use server_utils::*;

// Main function that drives the application
#[tokio::main]
async fn main() {
    // Initialize tracing
    setup_tracing();

    // Set up the server
    let bind_address = "0.0.0.0:3000";
    let (listener, app) = setup_server(bind_address).await;
    
    // Start the server
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}