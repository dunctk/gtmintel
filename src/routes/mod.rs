// Export all route modules
pub mod content_suggestions;
pub mod industry_news;
pub mod accessibility;

// Re-export all route handlers for easy importing
pub use content_suggestions::*;
pub use industry_news::*;
pub use accessibility::*; 