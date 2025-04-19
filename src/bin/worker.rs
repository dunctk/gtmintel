use std::time::Duration;
use tokio::time::interval;
use tracing::{error, info};
use tracing_subscriber::FmtSubscriber;
use tracing::Level;
use gtmintel::jobs::run_industry_funding;
use gtmintel::jobs::run_industry_hiring_ads;
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
    let run_hiring_once = args.iter().any(|a| a == "--industry-hiring-ads");

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

    // Run industry funding job once if flag is set
    if run_once {
        if let Err(e) = run_industry_funding(db_conn.as_ref(), 0).await {
            error!(?e, "industry-funding job failed");
        }
        return;
    }

    // Run industry hiring job once if flag is set
    if run_hiring_once {
        if let Err(e) = run_industry_hiring_ads(db_conn.as_ref()).await {
            error!(?e, "industry-hiring-ads job failed");
        }
        return;
    }


    info!("Worker starting; running jobs every 15 minutes");

    let mut ticker = interval(Duration::from_secs(15 * 60));
    loop {
        ticker.tick().await;
        info!("Running scheduled jobs...");

        // Run funding job
        if let Err(e) = run_industry_funding(db_conn.as_ref(), 0).await {
            error!(?e, "industry-funding job failed");
        }

        // Run hiring ads job
        if let Err(e) = run_industry_hiring_ads(db_conn.as_ref()).await {
            error!(?e, "industry-hiring-ads job failed");
        }
        info!("Scheduled jobs finished.");
    }
} 