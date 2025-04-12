# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build/Run/Test Commands
- Build: `cargo build`
- Run: `cargo run`
- Test all: `cargo test`
- Test single: `cargo test test_name` (e.g., `cargo test test_health_endpoint`)
- Format: `cargo fmt`
- Lint: `cargo clippy`
- Check test coverage: `cargo llvm-cov --text`

## Code Style
- **Formatting**: Use standard Rust formatting with `cargo fmt`
- **Imports**: Group in order: std, external, crate-specific; use conditional compilation for test-only imports
- **Error Handling**: Use proper Result types with descriptive errors, add trace logs for errors
- **Naming**: Use snake_case for variables/functions, CamelCase for types, SCREAMING_CASE for constants
- **Types**: Type all structs, impl appropriate traits (Debug, Serialize/Deserialize, etc.)
- **Comments**: Explain the "why" not just "what", use doc comments (`///`) for public APIs
- **Testing**: Create direct test routers rather than using middleware-laden app

## Project Structure
- `/src`: Application source code
  - `lib.rs`: API routes, handlers, and core functionality
  - `main.rs`: Application entry point
- `/tests`: Integration tests