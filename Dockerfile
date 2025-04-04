FROM rust:1.73 as builder

WORKDIR /usr/src/pqsecure-mesh
COPY . .

# Install dependencies and build the project
RUN cargo build --release

# Use a smaller base image
FROM debian:bullseye-slim

# Install necessary SSL libraries and CA certificates
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from the build stage
COPY --from=builder /usr/src/pqsecure-mesh/target/release/pqsecure-mesh /app/
# Copy configuration files and policies
COPY --from=builder /usr/src/pqsecure-mesh/config /app/config
# Create necessary directories
RUN mkdir -p /app/data/certs /app/data/identity

# Set default environment variables
ENV PQSM__GENERAL__APP_NAME="PQSecure Mesh"
ENV PQSM__GENERAL__MODE="sidecar"
ENV PQSM__GENERAL__LOG_LEVEL="info"
ENV PQSM__GENERAL__DATA_DIR="/app/data"

ENV PQSM__API__LISTEN_ADDR="0.0.0.0"
ENV PQSM__API__LISTEN_PORT="8080"
ENV PQSM__API__PATH_PREFIX="/api/v1"

ENV PQSM__PROXY__LISTEN_ADDR="0.0.0.0"
ENV PQSM__PROXY__LISTEN_PORT="9090"

ENV PQSM__CERT__ENABLE_MTLS="true"
ENV PQSM__CERT__ENABLE_PQC="true"
ENV PQSM__CERT__CA_TYPE="mock"

# Expose API and Proxy ports
EXPOSE 8080 9090 9091

# Run the application
CMD ["/app/pqsecure-mesh"]