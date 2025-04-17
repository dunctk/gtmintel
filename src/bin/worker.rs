use std::time::Duration;
use tokio::time::interval;
use tracing::{error, info};
use tracing_subscriber::FmtSubscriber;
use tracing::Level;
use gtmintel::jobs::run_industry_funding;
use std::env;

// Placeholder async job function. Replace its body with real logic that
// fetches fresh market data from an external API and persists it to your
// database.
async fn fetch_market_data_and_store() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Delegate to the real job (days_back = 0)
    run_industry_funding(0).await
}

#[tokio::main]
async fn main() {
    // Initialise tracing (INFO level)
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    // ---------------------------------------------------------------------------------
    // Command‑line flags
    // ---------------------------------------------------------------------------------
    let args: Vec<String> = env::args().collect();
    let run_once = args.iter().any(|a| a == "--industry-funding");

    if run_once {
        // Immediate, single‑shot execution
        if let Err(e) = fetch_market_data_and_store().await {
            error!(?e, "industry‑funding job failed");
        }
        return; // exit after one run
    }

    info!("industry‑funding worker starting; running every 15 minutes");

    // Schedule: every 15 minutes
    let mut ticker = interval(Duration::from_secs(15 * 60));
    loop {
        ticker.tick().await; // Wait until the next instant
        if let Err(e) = fetch_market_data_and_store().await {
            error!(?e, "industry‑funding job failed");
        }
    }
} 