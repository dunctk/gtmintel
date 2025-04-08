# GTM INTEL API

[**API Docs**](https://api.gtmintel.com/docs/) | [**OpenAPI Specification (JSON)**](https://api.gtmintel.com/api-doc/openapi.json)

API for [GTM INTEL](https://gtmintel.com)

A Rust-based API service for company research and website analysis.

## Features

- Get the number of new pages published on a domain in the last 7 days
- OpenAPI documentation with Swagger UI
- CORS support
- Built with Axum framework

## Getting Started

### Prerequisites

- Rust (latest stable version)
- Cargo (comes with Rust)

### Installation

1. Clone the repository
2. Navigate to the project directory
3. Run the server:
   ```bash
   cargo run
   ```

The server will start on `http://127.0.0.1:3000`

## API Documentation

Swagger UI documentation is available at: `http://127.0.0.1:3000/docs`

### Endpoints

#### GET /research/pages

Get the number of new pages published in the last 7 days for a given domain.

Query Parameters:
- `domain` (required): The domain name to analyze (e.g., "example.com")
- `within_days` (optional, default: 7): Number of days in the past to check.
- `list_pages` (optional, default: false): Set to `true` to include the list of updated page URLs.

Example Response (without `list_pages=true`):
```json
{
  "domain": "example.com",
  "updated_pages": 42,
  "days_analyzed": 7,
  "sitemap_url": "https://example.com/sitemap.xml"
}
```

Example Response (with `list_pages=true`):
```json
{
  "domain": "example.com",
  "updated_pages": 2,
  "days_analyzed": 7,
  "sitemap_url": "https://example.com/sitemap.xml",
  "updated_page_urls": [
    "https://example.com/new-page-1",
    "https://example.com/updated-blog-post"
  ]
}
```

## Development

To build the project:
```bash
cargo build
```

To run tests:
```bash
cargo test
```

## License

MIT 