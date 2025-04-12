use std::net::SocketAddr;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::Level;

#[tokio::test]
async fn test_main_server_startup() {
    // Initialize tracing for tests
    let _ = tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .try_init();
    
    // Start the server in a separate task
    let server_task: JoinHandle<()> = tokio::spawn(async {
        // Use a different port than the main application to avoid conflicts
        let app = gtmintel::create_app();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:3030").await.unwrap();
        tracing::info!("Test server running on http://127.0.0.1:3030");
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    
    // Wait a moment for the server to start up
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Make a request to the server to test it's running
    let client = reqwest::Client::new();
    let result = client.get("http://127.0.0.1:3030/health").send().await;
    
    // Cancel the server task after we've made our test request
    server_task.abort();
    
    // Check if the server responded - note that in a test env without all
    // dependencies initialized, this might result in a 500 status
    // but we're just testing that the server is running and responds
    if let Ok(response) = result {
        println!("Server test status: {}", response.status());
        assert!(response.status().is_success() || 
                response.status().is_server_error());
    } else {
        // If we couldn't connect, that suggests the server didn't start
        // But this test is successful if the server started - we're not testing
        // specific response codes in this test
        assert!(false, "Failed to connect to test server");
    }
}