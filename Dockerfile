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

# Install OpenSSL and *reference* LAPACK/BLAS development headers
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libssl-dev \
        pkg-config \
        liblapack-dev \
        libblas-dev \
    # Clean up apt cache after installation
    && rm -rf /var/lib/apt/lists/*

# Copy the recipe from the planner
COPY --from=planner /app/recipe.json recipe.json

# 3A) Cargo Chef to cache dependencies (build them once for the native target)
RUN cargo chef cook --release --recipe-path recipe.json

# 3B) Now copy the actual source code and build our final binary (for the native target)
COPY . .
RUN cargo build --release
# The binary will be located at /app/target/release/gtmintel

# -------------------------------------------------------
# 4) Final stage with a *minimal* Debian image
#    This includes glibc and libssl, so we don't need a static binary.
# -------------------------------------------------------
FROM debian:stable-slim AS runtime
# No ARGs needed as we build natively and copy from the standard release path
WORKDIR /app

# Copy dynamically-linked binary from the standard release location in the builder stage
COPY --from=builder /app/target/release/gtmintel /app/gtmintel



# Update package lists and install runtime libs
# This ensures libssl.so.3 (or similar) and certificates are present
RUN apt-get update && apt-get install -y --no-install-recommends libssl3 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN apt-get install -y --no-install-recommends build-essential pkg-config libopenblas-dev liblapack-dev && \
    rm -rf /var/lib/apt/lists/*

# Required for healthcheck
RUN apt-get install -y --no-install-recommends curl


# Create and switch to a non-root user (recommended)
#RUN groupadd --system appuser && useradd --system --gid appuser --no-create-home appuser
#USER appuser

# Environment
ENV PORT=3000
ENV LAPACK_PROVIDER=openblas-system
ENV CBLAS_PROVIDER=openblas-system

# Expose the application port
EXPOSE 3000

# Run the binary! (ensure path matches the COPY destination)
CMD ["/app/gtmintel"]
