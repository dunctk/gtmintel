use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Deserialize, Serialize)]
#[sea_orm(table_name = "industry_hiring_ads")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i32, // Internal primary key
    #[sea_orm(unique)]
    pub linkedin_id: String, // Use the 'id' from JSON as a unique identifier
    pub tracking_id: Option<String>,
    pub ref_id: Option<String>,
    pub link: String,
    pub title: String,
    pub company_name: String,
    pub company_linkedin_url: Option<String>,
    pub company_logo: Option<String>,
    pub location: Option<String>,
    #[sea_orm(column_type = "JsonBinary", nullable)]
    pub salary_info: Option<Json>, // Store as JSON
    pub posted_at: Option<Date>, // Store as Date
    #[sea_orm(column_type = "JsonBinary", nullable)]
    pub benefits: Option<Json>, // Store as JSON
    pub description_html: String,
    pub applicants_count: Option<String>, // Keep as string as in JSON
    pub apply_url: Option<String>,
    pub description_text: String,
    pub seniority_level: Option<String>,
    pub employment_type: Option<String>,
    pub job_function: Option<String>,
    pub industries: Option<String>,
    pub input_url: Option<String>, // URL used for scraping
    pub company_description: Option<String>,
    #[sea_orm(column_type = "JsonBinary", nullable)]
    pub company_address: Option<Json>, // Store as JSON
    pub company_website: Option<String>,
    pub company_slogan: Option<String>,
    pub company_employees_count: Option<i32>,
    // Enrichment/Filtering fields (placeholders for now)
    pub is_relevant: Option<bool>,
    pub enrichment_data: Option<Json>,
    // Timestamps
    #[sea_orm(default_expr = "Expr::current_timestamp()")]
    pub created_at: DateTime<Utc>,
    #[sea_orm(default_expr = "Expr::current_timestamp()", on_update = "Expr::current_timestamp()")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

// Helper struct for deserializing the JSON list items
// We'll map this to the ActiveModel for insertion
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JobListing {
    pub id: String, // linkedin_id
    pub tracking_id: Option<String>,
    pub ref_id: Option<String>,
    pub link: String,
    pub title: String,
    pub company_name: String,
    pub company_linkedin_url: Option<String>,
    pub company_logo: Option<String>,
    pub location: Option<String>,
    #[serde(default)] // Handle missing or null salaryInfo
    pub salary_info: Option<serde_json::Value>,
    #[serde(default)] // Handle missing or null postedAt
    pub posted_at: Option<String>, // Parse this string to Date later
    #[serde(default)] // Handle missing or null benefits
    pub benefits: Option<serde_json::Value>,
    pub description_html: String,
    pub applicants_count: Option<String>,
    pub apply_url: Option<String>,
    pub description_text: String,
    pub seniority_level: Option<String>,
    pub employment_type: Option<String>,
    pub job_function: Option<String>,
    pub industries: Option<String>,
    pub input_url: Option<String>,
    pub company_description: Option<String>,
    #[serde(default)] // Handle missing or null companyAddress
    pub company_address: Option<serde_json::Value>,
    pub company_website: Option<String>,
    pub company_slogan: Option<String>,
    pub company_employees_count: Option<i32>,
} 