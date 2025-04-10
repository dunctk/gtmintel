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
RUN cargo chef prepare --recipe-path recipe.json --target aarch64-unknown-linux-gnu

# -------------------------------------------------------
# 3) Builder stage: build dependencies + final binary FOR ARM64
# -------------------------------------------------------
FROM chef AS builder
WORKDIR /app

# Add the ARM64 target to the Rust toolchain
RUN rustup target add aarch64-unknown-linux-gnu

# Install build-essential, OpenSSL, OpenBLAS, AND the cross-compilation linker for ARM64
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    pkg-config \
    libopenblas-dev \
    gcc-aarch64-linux-gnu \
    # Clean up apt cache after installation
    && rm -rf /var/lib/apt/lists/*

# Configure Cargo to use the cross-linker for the ARM64 target
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
ENV PKG_CONFIG_ALLOW_CROSS=1

# Copy the recipe from the planner
COPY --from=planner /app/recipe.json recipe.json

# 3A) Cargo Chef to cache dependencies (build them for the ARM64 target)
RUN cargo chef cook --release --recipe-path recipe.json --target aarch64-unknown-linux-gnu

# 3B) Now copy the actual source code and build our final binary (for the ARM64 target)
COPY . .
RUN cargo build --release --target aarch64-unknown-linux-gnu
# The ARM64 binary will be located at /app/target/aarch64-unknown-linux-gnu/release/gtmintel

# -------------------------------------------------------
# 4) Final stage with a *minimal* Debian image (Docker will pull ARM64 version if host is ARM64)
#    This includes glibc and libssl, so we don't need a static binary.
# -------------------------------------------------------
FROM debian:stable-slim AS runtime
# No ARGs needed as we build natively and copy from the standard release path
WORKDIR /app

# Copy the cross-compiled ARM64 binary from the builder stage
COPY --from=builder /app/target/aarch64-unknown-linux-gnu/release/gtmintel /app/gtmintel

# Update package lists and install runtime libs for ARM64
# This ensures libssl.so.3 (or similar) and certificates are present
# Also add libopenblas0 for runtime BLAS/LAPACK linkage
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    ca-certificates \
    libopenblas0 \
    && rm -rf /var/lib/apt/lists/*

# Create and switch to a non-root user (recommended)
RUN groupadd --system appuser && useradd --system --gid appuser --no-create-home appuser
USER appuser

# Environment
ENV PORT=3000

# Expose the application port
EXPOSE 3000

# Run the binary! (ensure path matches the COPY destination)
CMD ["/app/gtmintel"]
