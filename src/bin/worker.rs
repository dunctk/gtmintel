use std::time::Duration;
use tokio::time::interval;
use tracing::{error, info};
use tracing_subscriber::FmtSubscriber;
use tracing::Level;
use gtmintel::jobs::run_industry_funding;
use std::env;
use sea_orm::{Database, DatabaseConnection};
use dotenvy::dotenv;

#[tokio::main]
async fn main() {
    // Initialise tracing (INFO level)
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    // Load .env (if present) so DATABASE_URL from file is visible
    let _ = dotenv();

    // Command‑line flags
    let args: Vec<String> = env::args().collect();
    let run_once = args.iter().any(|a| a == "--industry-funding");

    // Establish DB connection (if DATABASE_URL is set) — optional for local runs
    let db_conn: Option<DatabaseConnection> = match env::var("DATABASE_URL") {
        Ok(url) => {
            match Database::connect(&url).await {
                Ok(conn) => Some(conn),
                Err(e) => {
                    error!(?e, "failed to connect to database");
                    None
                }
            }
        }
        Err(_) => {
            info!("DATABASE_URL not set; continuing without DB");
            None
        }
    };

    if run_once {
        if let Err(e) = run_industry_funding(db_conn.as_ref(), 0).await {
            error!(?e, "industry‑funding job failed");
        }
        return;
    }

    // Notify immediately that the worker has started and is scheduling
    println!("industry-funding worker started; scheduling every 15 minutes");

    info!("industry‑funding worker starting; running every 15 minutes");

    let mut ticker = interval(Duration::from_secs(15 * 60));
    loop {
        ticker.tick().await;
        if let Err(e) = run_industry_funding(db_conn.as_ref(), 0).await {
            error!(?e, "industry‑funding job failed");
        }
    }
} 