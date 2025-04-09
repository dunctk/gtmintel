# GTM INTEL API
[![Actions Status](https://github.com/dunctk/gtmintel/workflows/Rust_Tests/badge.svg)](https://github.com/dunctk/gtmintel/actions)
 [![Codecov](https://codecov.io/gh/dunctk/gtmintel//branch/main/graph/badge.svg)](https://codecov.io/gh/dunctk/gtmintel)


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

This project is licensed under the Sustainable Use License. For details, see [LICENSE.md](LICENSE.md)

## Sustainable Use License FAQ

Our Sustainable Use License is based on the principles of [fair-code](https://faircode.io/) and is similar to the license used by [n8n](https://docs.n8n.io/sustainable-use-license/).

### What is "fair-code" and why did I choose it?

Fair-code isn't a software license, but a software model that aims to create a balance between openness and sustainability. Under fair-code, software:

- Is generally free to use and can be distributed by anybody
- Has its source code openly available
- Can be extended by anybody in public and private communities
- Is commercially restricted by its authors

I chose this model to ensure GTM INTEL API can remain sustainable while still providing most of the benefits of open source software.

### Can I use GTM INTEL API for free?

Yes! You can use GTM INTEL API completely free of charge for internal business purposes. This means you can use it within your organization, even if you have thousands of employees.

### What uses are restricted?

You may not use GTM INTEL API to create a commercial offering or service that competes with GTM INTEL. Specifically, you cannot:

- Host GTM INTEL API as a service for others
- Include GTM INTEL API in a commercial product offering that provides substantially similar functionality
- Rebrand GTM INTEL API as your own offering

### Can I offer consulting or support services for GTM INTEL API?

Yes! You are free to offer commercial consulting or support services related to GTM INTEL API without needing a separate agreement with us.

### Is GTM INTEL API open source?

While GTM INTEL API's source code is openly available, it does not use an Open Source Initiative (OSI) approved license. According to OSI, open source licenses cannot include limitations on use, so I use the term "fair-code" instead. In practice, GTM INTEL API offers most users many of the same benefits as OSI-approved open source.

### Why did I choose this license model?

I want to:
1. Be as permissive as possible
2. Safeguard our ability to build a sustainable business
3. Be clear about what use is permitted

If you have any questions about licensing or permitted use cases, please contact us. 