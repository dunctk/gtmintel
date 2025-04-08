# -------------------------------------------------------
# 1) Base image with Rust + cargo-chef
# -------------------------------------------------------
FROM rust:1.84 AS chef
WORKDIR /app

# Install cargo-chef (for caching)
RUN cargo install cargo-chef

# -------------------------------------------------------
# 2) Planner stage: create the "recipe.json" for caching
# -------------------------------------------------------
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# -------------------------------------------------------
# 3) Builder stage: build dependencies + final binary
# -------------------------------------------------------
FROM chef AS builder
WORKDIR /app

# Install OpenSSL development headers before building (needed for dynamic linking)
RUN apt-get update && apt-get install -y --no-install-recommends libssl-dev pkg-config && \
    rm -rf /var/lib/apt/lists/*

# Copy the recipe from the planner
COPY --from=planner /app/recipe.json recipe.json

# 3A) Cargo Chef to cache dependencies (build them once)
RUN cargo chef cook --release --recipe-path recipe.json

# 3B) Now copy the actual source code and build our final binary
COPY . .
RUN cargo build --release

# -------------------------------------------------------
# 4) Final stage with a *minimal* Debian image
#    This includes glibc and libssl, so we don't need a static binary.
# -------------------------------------------------------
FROM debian:stable-slim AS runtime
# Use the architecture of your builder image (e.g., aarch64 or amd64)
# Adjust TARGET_ARCH and TARGET_FOLDER if your base image architecture differs.
ARG TARGET_ARCH=aarch64
ARG TARGET_FOLDER=${TARGET_ARCH}-unknown-linux-gnu
WORKDIR /app

# Copy dynamically-linked binary from builder (update path)
COPY --from=builder /app/target/${TARGET_FOLDER}/release/gtmintel /app/gtmintel

# Copy the static directory for serving static files
COPY --from=builder /app/static /app/static

# Update package lists and install runtime libs
# This ensures libssl.so.3 (or similar) and certificates are present
RUN apt-get update && apt-get install -y --no-install-recommends libssl3 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Create and switch to a non-root user (recommended)
RUN groupadd --system appuser && useradd --system --gid appuser --no-create-home appuser
USER appuser

# (Optional) If you do want to run as a non-root user, you can switch to Alpine:
# FROM alpine:3.17 AS runtime
# RUN addgroup -S appuser && adduser -S appuser -G appuser
# USER appuser

# Environment
# Set PORT (common convention) instead of ROCKET_* unless specifically needed
# ENV ROCKET_ADDRESS=0.0.0.0
# ENV ROCKET_PORT=8000
ENV PORT=8000

# Expose the application port
EXPOSE 8000

# Run the binary! (update path)
CMD ["/app/gtmintel"]
