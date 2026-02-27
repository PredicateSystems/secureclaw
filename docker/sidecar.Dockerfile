# Dockerfile for rust-predicate-authorityd sidecar
# Multi-stage build for smaller final image
#
# Build options:
#   1. With local source: docker build --build-arg SIDECAR_SRC=../rust-predicate-authorityd
#   2. From git: docker build (uses git clone)

# ============================================================================
# Stage 1: Build the Rust sidecar
# ============================================================================
FROM rust:1.75-slim-bookworm AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Clone the sidecar source from git
# In production, pin to a specific tag/commit
RUN git clone --depth 1 https://github.com/rcholic/rust-predicate-authorityd.git . || \
    git clone --depth 1 https://github.com/predicatesystems/rust-predicate-authorityd.git .

# Build release binary
RUN cargo build --release

# ============================================================================
# Stage 2: Runtime image
# ============================================================================
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy the built binary
COPY --from=builder /build/target/release/predicate-authorityd /usr/local/bin/

# Create policies directory
RUN mkdir -p /app/policies

# Create non-root user
RUN useradd -m -s /bin/bash predicate
USER predicate

# Default port
EXPOSE 8787

# Health check
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8787/health || exit 1

# Default command - policy file should be mounted or provided
ENTRYPOINT ["predicate-authorityd"]
CMD ["--policy", "/app/policies/default.json", "--port", "8787", "--bind", "0.0.0.0"]