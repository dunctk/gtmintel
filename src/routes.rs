use axum::{routing::get, Router};
use askama::Template;
use askama_axum::IntoResponse;
use tower_http::services::ServeDir;

// Import Turf for SCSS styling
use turf::inline_style_sheet_values;

// Template Structs (can stay here or move to components.rs/models.rs)
#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    style_sheet: &'static str,
    class_names: ClassNames,
}

#[derive(Template)]
#[template(path = "widget.html")]
struct WidgetTemplate {
    message: String,
    style_sheet: &'static str,
    class_names: ClassNames,
}

// Generate CSS from SCSS and create struct for class name access
struct ClassNames {
    container: &'static str,
    card: &'static str,
    title: &'static str,
    content: &'static str,
    button: &'static str,
    widget: &'static str,
}

// Use inline style sheet for example purposes
// In production, you'd typically use style_sheet!("scss/main.scss") instead
lazy_static::lazy_static! {
    static ref COMPILED_CSS: (&'static str, ClassNames) = {
        let (css, class_map) = inline_style_sheet_values! {
            .Container {
                font-family: "Inter", system-ui, -apple-system, sans-serif;
                color: #FFFFFF;
                background-color: #121218;
                min-height: 100vh;
                padding: 2rem;
                box-sizing: border-box;
            }
            
            .Card {
                background-color: #1E1E24;
                border-radius: 8px;
                padding: 1.5rem;
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.35);
                margin-bottom: 1.5rem;
            }
            
            .Title {
                color: #8A2BE2;
                font-size: 1.5rem;
                margin-top: 0;
                margin-bottom: 1rem;
            }
            
            .Content {
                color: #9E9EA7;
                line-height: 1.5;
            }
            
            .Button {
                background: linear-gradient(to right, #8A2BE2, #FF1493);
                color: #FFFFFF;
                border: none;
                border-radius: 8px;
                padding: 0.75rem 1.5rem;
                font-weight: 600;
                cursor: pointer;
                transition: 300ms ease;
                
                &:hover {
                    opacity: 0.9;
                    transform: translateY(-2px);
                }
            }
            
            .Widget {
                background-color: #2A2A30;
                border-radius: 8px;
                padding: 1rem;
                margin-top: 1rem;
            }
        };
        
        // Create our ClassNames struct with the generated class names
        let class_names = ClassNames {
            container: class_map.container,
            card: class_map.card,
            title: class_map.title,
            content: class_map.content,
            button: class_map.button,
            widget: class_map.widget,
        };
        
        (css, class_names)
    };
}

// Function to create the main application router
pub fn create_router() -> Router {
    Router::new()
        // Serve static files from the `static` directory
        .nest_service("/static", ServeDir::new("static"))
        // Application routes
        .route("/", get(root_handler_askama))
        .route("/load-widget", get(load_widget_handler))
}


// Handlers
async fn root_handler_askama() -> impl IntoResponse {
    let template = IndexTemplate {
        style_sheet: COMPILED_CSS.0,
        class_names: COMPILED_CSS.1.clone(),
    };
    template
}

async fn load_widget_handler() -> impl IntoResponse {
    let template = WidgetTemplate {
        message: "Content loaded via HTMX!".to_string(),
        style_sheet: COMPILED_CSS.0,
        class_names: COMPILED_CSS.1.clone(),
    };
    template
}

// Automatically implement Clone for ClassNames
impl Clone for ClassNames {
    fn clone(&self) -> Self {
        Self {
            container: self.container,
            card: self.card,
            title: self.title,
            content: self.content,
            button: self.button,
            widget: self.widget,
        }
    }
} 