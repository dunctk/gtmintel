mod db;
mod fileserv;

use axum::{Router, routing::get};
use dotenv::dotenv;
use leptos::*;
use leptos_axum::{generate_route_list, LeptosRoutes};
use std::env;

#[tokio::main]
async fn main() {
    // Load environment variables from .env file
    dotenv().ok();
    
    // Connect to the database
    let db_conn = db::connect().await.expect("Failed to connect to database");
    
    // Existing Axum server setup
    let leptos_options = LeptosOptions::builder().output_name("app").build();
    
    // Create a router with routes and database connection state
    let app = Router::new()
        .leptos_routes(&leptos_options, generate_route_list(app::App), app::App)
        .with_state((leptos_options, db_conn)); // Add database connection to state
    
    // Start the server
    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
