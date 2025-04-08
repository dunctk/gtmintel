# -------------------------------------------------------
# 1) Base image with Rust + cargo-chef
#    We'll install the `aarch64-unknown-linux-musl` target
# -------------------------------------------------------
FROM rust:1.84 AS chef
WORKDIR /app

# Install cargo-chef (for caching) and musl tools (for static linking)
RUN cargo install cargo-chef
RUN apt-get update && apt-get install -y musl-tools && rm -rf /var/lib/apt/lists/*
RUN rustup target add aarch64-unknown-linux-musl

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

# Copy the recipe from the planner
COPY --from=planner /app/recipe.json recipe.json

# 3A) Cargo Chef to cache dependencies (build them once)
RUN cargo chef cook --release --target aarch64-unknown-linux-musl --recipe-path recipe.json

# 3B) Now copy the actual source code and build our final binary
COPY . .
RUN cargo build --release --target aarch64-unknown-linux-musl

# -------------------------------------------------------
# 4) Final stage with a *minimal* image
#    Since it's fully static, you can use FROM scratch
#    or a small base like alpine if you want a shell
# -------------------------------------------------------
FROM scratch AS runtime

# Copy our statically-linked binary from builder
COPY --from=builder /app/target/aarch64-unknown-linux-musl/release/gtmintel /gtmintel

# Copy the static directory for serving static files
COPY --from=builder /app/static /static

# (Optional) If you do want to run as a non-root user, you can switch to Alpine:
# FROM alpine:3.17 AS runtime
# RUN addgroup -S appuser && adduser -S appuser -G appuser
# USER appuser

# Environment
ENV ROCKET_ADDRESS=0.0.0.0
ENV ROCKET_PORT=8000

# Expose the Rocket port
EXPOSE 8000

# Run the binary!
CMD ["/gtmintel"]
