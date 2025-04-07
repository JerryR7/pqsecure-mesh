FROM rust:1.86 as builder

WORKDIR /app

# Copy over manifests and src
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Build with optimizations
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release && \
    cp target/release/pqsecure-mesh /app/pqsecure-mesh

# Create runtime image
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user and directories
RUN useradd -m -u 1000 -s /bin/bash pqsecure && \
    mkdir -p /app/config /app/certs && \
    chown -R pqsecure:pqsecure /app

# Copy binary from builder
COPY --from=builder /app/pqsecure-mesh /app/pqsecure-mesh

# Copy config files
COPY config/ /app/config/

# Set permissions
RUN chmod +x /app/pqsecure-mesh && \
    chown -R pqsecure:pqsecure /app

# Switch to non-root user
USER pqsecure
WORKDIR /app

# Set environment variables
ENV RUST_LOG=info

# Expose port
EXPOSE 8443

# Run the service
CMD ["/app/pqsecure-mesh"]