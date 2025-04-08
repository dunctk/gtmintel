# GTMintel API

[OpenAPI Specification](https://api.gtmintel.com/api-doc/openapi.json)

API for [gtmintel](https://gtmintel.com)

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

Example Response:
```json
{
  "domain": "example.com",
  "new_pages_last_7_days": 42
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