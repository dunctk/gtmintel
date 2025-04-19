pub use sea_orm_migration::prelude::*;

mod m20250419_153514_create_industry_hiring_ads_table; mod m20250419_154927_create_funding_table;
// Renamed migration file
// Add other migration modules here if you have more

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20250419_153514_create_industry_hiring_ads_table::Migration),
            Box::new(m20250419_154927_create_funding_table::Migration),
        ]
    }
} 