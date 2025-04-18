use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(IndustryHiringAds::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(IndustryHiringAds::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(IndustryHiringAds::LinkedinId)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(IndustryHiringAds::TrackingId).string().null())
                    .col(ColumnDef::new(IndustryHiringAds::RefId).string().null())
                    .col(ColumnDef::new(IndustryHiringAds::Link).string().not_null())
                    .col(ColumnDef::new(IndustryHiringAds::Title).string().not_null())
                    .col(ColumnDef::new(IndustryHiringAds::CompanyName).string().not_null())
                    .col(ColumnDef::new(IndustryHiringAds::CompanyLinkedinUrl).string().null())
                    .col(ColumnDef::new(IndustryHiringAds::CompanyLogo).string().null())
                    .col(ColumnDef::new(IndustryHiringAds::Location).string().null())
                    .col(ColumnDef::new(IndustryHiringAds::SalaryInfo).json_binary().null())
                    .col(ColumnDef::new(IndustryHiringAds::PostedAt).date().null())
                    .col(ColumnDef::new(IndustryHiringAds::Benefits).json_binary().null())
                    .col(ColumnDef::new(IndustryHiringAds::DescriptionHtml).text().not_null())
                    .col(ColumnDef::new(IndustryHiringAds::ApplicantsCount).string().null())
                    .col(ColumnDef::new(IndustryHiringAds::ApplyUrl).string().null())
                    .col(ColumnDef::new(IndustryHiringAds::DescriptionText).text().not_null())
                    .col(ColumnDef::new(IndustryHiringAds::SeniorityLevel).string().null())
                    .col(ColumnDef::new(IndustryHiringAds::EmploymentType).string().null())
                    .col(ColumnDef::new(IndustryHiringAds::JobFunction).string().null())
                    .col(ColumnDef::new(IndustryHiringAds::Industries).string().null())
                    .col(ColumnDef::new(IndustryHiringAds::InputUrl).string().null())
                    .col(ColumnDef::new(IndustryHiringAds::CompanyDescription).text().null())
                    .col(ColumnDef::new(IndustryHiringAds::CompanyAddress).json_binary().null())
                    .col(ColumnDef::new(IndustryHiringAds::CompanyWebsite).string().null())
                    .col(ColumnDef::new(IndustryHiringAds::CompanySlogan).string().null())
                    .col(ColumnDef::new(IndustryHiringAds::CompanyEmployeesCount).integer().null())
                    .col(ColumnDef::new(IndustryHiringAds::IsRelevant).boolean().null())
                    .col(ColumnDef::new(IndustryHiringAds::EnrichmentData).json_binary().null())
                    .col(
                        ColumnDef::new(IndustryHiringAds::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(IndustryHiringAds::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(IndustryHiringAds::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum IndustryHiringAds {
    Table,
    Id,
    LinkedinId,
    TrackingId,
    RefId,
    Link,
    Title,
    CompanyName,
    CompanyLinkedinUrl,
    CompanyLogo,
    Location,
    SalaryInfo,
    PostedAt,
    Benefits,
    DescriptionHtml,
    ApplicantsCount,
    ApplyUrl,
    DescriptionText,
    SeniorityLevel,
    EmploymentType,
    JobFunction,
    Industries,
    InputUrl,
    CompanyDescription,
    CompanyAddress,
    CompanyWebsite,
    CompanySlogan,
    CompanyEmployeesCount,
    IsRelevant,
    EnrichmentData,
    CreatedAt,
    UpdatedAt,
}
