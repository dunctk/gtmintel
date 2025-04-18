use sea_orm::entity::prelude::*;
use chrono::{DateTime, Utc};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "funding")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i64,                           // ← BIGINT maps to i64
    pub ts: String,
    pub source: String,
    pub amount_text: String,
    pub stage: String,
    pub news_url: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
