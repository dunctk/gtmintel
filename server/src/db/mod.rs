use sea_orm::{Database, DatabaseConnection, DbErr};
use std::env;

pub async fn connect() -> Result<DatabaseConnection, DbErr> {
    // Get the database type from environment variable
    let db_type = env::var("DB_TYPE").unwrap_or_else(|_| "sqlite".to_string());
    
    let db_url = match db_type.as_str() {
        "postgres" => {
            // Use Supabase Postgres
            env::var("DATABASE_URL").expect("DATABASE_URL must be set for Postgres")
        },
        _ => {
            // Default to SQLite for development
            env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:./local_db.sqlite?mode=rwc".to_string())
        }
    };
    
    println!("Connecting to database: {}", if db_type == "postgres" { "PostgreSQL (Supabase)" } else { "SQLite (local)" });
    
    Database::connect(&db_url).await
} 