# PQSecure Mesh 🦀

Post-Quantum Secure Proxy for Microservices – powered by Rust

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## 🔐 Features

- **Post-Quantum Cryptography (PQC)** - Support for quantum-resistant algorithms like Kyber/Dilithium for TLS certificates
- **Mutual TLS Authentication (mTLS)** - Every service uses X.509 certificates for secure communication
- **RESTful API Certificate Management** - Simple API for issuing and revoking certificates
- **Smallstep CA Integration** - Works with Smallstep or custom CA systems
- **Lightweight Sidecar Design** - Each microservice has its own proxy
- **High-Performance Rust Implementation** - Secure, efficient, small binary footprint
- **Container-Friendly** - Designed for Kubernetes and containerized environments

## 📋 Project Description

PQSecure Mesh is a secure Sidecar Proxy written in Rust, specifically designed to protect communication between microservices. Unlike mainstream service meshes (such as Istio), it focuses on providing post-quantum level security to address future threats from quantum computers.

This project is suitable for:
- Microservice architectures requiring high-strength security protection
- Forward-looking deployments against quantum computing threats
- Teams needing simple, efficient mTLS management
- Projects seeking API Gateway + Service Mesh integration solutions

## 🚀 Quick Start

### Local Run

```bash
# Clone the repository
git clone https://github.com/your-username/pqsecure-mesh.git
cd pqsecure-mesh

# Build the project
cargo build --release

# Run (in development mode)
cargo run --release
```

### Using Docker

```bash
# Build Docker image
docker build -t pqsecure-mesh .

# Run container
docker run -p 8080:8080 -p 9090:9090 pqsecure-mesh
```

### Configuration Options

PQSecure Mesh can be configured via environment variables or configuration files:

```bash
# Using environment variables
export PQSM__CERT__ENABLE_PQC=true
export PQSM__API__LISTEN_PORT=8443

# Or specify a configuration file
export CONFIG_FILE=/path/to/config.toml
```

## 📝 API Documentation

### Request Certificate

```bash
curl -X POST http://localhost:8080/api/v1/certs/request \
  -H "Content-Type: application/json" \
  -d '{
    "service_name": "my-service",
    "namespace": "default",
    "post_quantum": true
  }'
```

### Revoke Certificate

```bash
curl -X POST http://localhost:8080/api/v1/certs/revoke \
  -H "Content-Type: application/json" \
  -d '{
    "serial": "SERIAL_NUMBER",
    "reason": "keyCompromise"
  }'
```

### Check Certificate Status

```bash
curl http://localhost:8080/api/v1/certs/status/SERIAL_NUMBER
```

## 📚 Architecture

PQSecure Mesh follows Clean Architecture principles with the following project structure:

```
pqsecure-mesh/
├── src/
│   ├── domain/        - Core abstractions and models
│   ├── service/       - Business logic implementation
│   ├── infra/         - External system integrations
│   ├── interface/     - API and gRPC handlers
│   ├── config.rs      - Configuration management
│   └── main.rs        - Application entry point
```

## 🔗 Smallstep CA Integration

PQSecure Mesh can integrate with Smallstep CA for certificate management:

```bash
# Start Smallstep CA
docker run -p 9000:9000 \
  -v $PWD/step:/home/step \
  smallstep/step-ca

# Configure PQSecure Mesh
export PQSM__CERT__CA_TYPE=smallstep
export PQSM__CERT__SMALLSTEP_URL=https://ca.example.com
export PQSM__CERT__SMALLSTEP_TOKEN=your-bootstrap-token
```

## 👥 Contributing

Contributions are welcome! Please check out [CONTRIBUTING.md](CONTRIBUTING.md) for more information.

## 📜 License

This project is licensed under either MIT or Apache-2.0 - see the [LICENSE-MIT](LICENSE-MIT) or [LICENSE-APACHE](LICENSE-APACHE) files for details.