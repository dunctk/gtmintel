use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Funding::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Funding::Id)
                            .big_integer() // Corresponds to i64
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Funding::Ts).string().not_null()) // Assuming string based on entity
                    .col(ColumnDef::new(Funding::Source).string().not_null())
                    .col(ColumnDef::new(Funding::AmountText).string().not_null())
                    .col(ColumnDef::new(Funding::Stage).string().not_null())
                    .col(ColumnDef::new(Funding::NewsUrl).string().not_null().unique_key()) // Added unique key based on usage in funding job
                    .col(
                        ColumnDef::new(Funding::CreatedAt)
                            .timestamp_with_time_zone() // Corresponds to DateTime<Utc>
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(ColumnDef::new(Funding::ArticleContent).text().not_null()) // Use text for potentially long content
                    .col(ColumnDef::new(Funding::StageChecked).string().not_null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Funding::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Funding {
    Table,
    Id,
    Ts,
    Source,
    AmountText,
    Stage,
    NewsUrl,
    CreatedAt,
    ArticleContent,
    StageChecked,
}
