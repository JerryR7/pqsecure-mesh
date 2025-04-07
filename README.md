# PQSecure Mesh 🦀

Post-Quantum Secure Zero Trust Proxy for Microservices – powered by Rust

[![License: BSL-1.1](https://img.shields.io/badge/license-BSL--1.1-blue)](LICENSE)

## 🔐 Key Features

- **Post-Quantum Cryptography (PQC)** – Supports NIST standardized Kyber/Dilithium algorithms to defend against quantum threats
- **Zero Trust Architecture** – Identity-centric security model with authentication and authorization for every connection
- **SPIFFE Identity Integration** – Manage service identities using standardized SPIFFE IDs
- **Sidecar Transparent Proxy** – Enables PQC and mTLS communication without modifying existing applications
- **Multi-Protocol Support** – Works with HTTP, gRPC, and generic TCP protocols
- **Policy-Driven Access Control** – Flexible access control with YAML-based policies
- **Seamless Smallstep CA Integration** – Integrates smoothly with modern PKI solutions
- **Built with Rust** – High-performance, memory-safe implementation with async I/O

## 📋 Project Overview

**PQSecure Mesh** is a secure sidecar proxy designed to protect communication between microservices. Unlike traditional service meshes, it focuses on delivering post-quantum-grade security to counter the emerging threat of quantum computing.

Ideal for:
- Microservice architectures requiring high-level security
- Forward-looking deployments against quantum threats
- Teams seeking simple and efficient mTLS management
- Projects looking to combine API gateway and service mesh functionality

## 🚀 Getting Started

### Run Locally

```bash
# Clone the project
git clone https://github.com/JerryR7/pqsecure-mesh.git
cd pqsecure-mesh

# Build the project
cargo build --release

# Create required directories
mkdir -p certs config

# Setup example config
cp config/config.yaml.example.example config/config.yaml.example
cp config/policy.yaml.example.example config/policy.yaml.example

# Edit configurations with your settings
# You'll need to configure Smallstep CA connection

# Run the service
RUST_LOG=info ./target/release/pqsecure-mesh
```

### Using Docker

```bash
# Build Docker image
docker build -t pqsecure-mesh .

# Run the container
docker run -p 8443:8443 \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/certs:/app/certs \
  -e SMALLSTEP_TOKEN=your_token_here \
  -e RUST_LOG=info \
  pqsecure-mesh
```

## 📚 Architecture

PQSecure Mesh follows a modular design with clean separation of concerns:

```
src/
├── main.rs                    # Program entry point
├── config/                    # Configuration management (serde_yaml + env)
│   └── mod.rs
├── telemetry/                 # tracing, OTEL support
│   └── mod.rs
├── common/                    # Shared DTO, errors, utilities
│   ├── types.rs               # DTO / base data models
│   ├── errors.rs              # thiserror definitions
│   └── utils.rs               # Common functions
├── identity/                  # SPIFFE identity verification module
│   └── verifier.rs            # SPIFFE ID checker
├── ca/                        # Smallstep CA certificate integration
│   ├── client.rs              # Smallstep API client
│   └── csr.rs                 # rcgen CSR request logic
├── crypto/                    # TLS + PQC certificate verifier
│   └── pqc_verifier.rs        # Custom rustls verifier
├── proxy/                     # Proxy module
│   ├── handler.rs             # trait: ConnectionHandler
│   ├── pqc_acceptor.rs        # TLS Listener
│   ├── forwarder.rs           # tokio::copy_bidirectional
│   └── protocol/              # Multi-protocol implementation
│       ├── raw_tcp.rs
│       ├── grpc.rs
│       └── http_tls.rs
├── policy/                    # ACL decision module
│   ├── engine.rs              # trait: PolicyEngine + evaluator
│   └── model.rs               # ACL rule definitions
```

## ⚙️ Configuration

PQSecure Mesh is configured through YAML files and environment variables:

### Main Configuration

```yaml
# config/config.yaml.example
ca:
  api_url: "https://ca.example.com:9000"
  cert_path: "./certs/cert.pem"
  key_path: "./certs/key.pem"
  token: "${SMALLSTEP_TOKEN}"
  spiffe_id: "spiffe://example.org/service/pqsecure-mesh"

identity:
  trusted_domain: "example.org"

policy:
  path: "./config/policy.yaml.example"

proxy:
  listen_addr: "0.0.0.0:8443"
  backend:
    address: "127.0.0.1:8080"
    timeout_seconds: 30
  protocols:
    tcp: true
    http: true
    grpc: true

telemetry:
  otel_endpoint: "http://otel-collector:4317"
  service_name: "pqsecure-mesh"
```

### Policy Configuration

Access control policies are defined in YAML:

```yaml
# config/policy.yaml.example
default_action: false
rules:
  # Allow all connections from monitoring
  - spiffe_id: "spiffe://example.org/service/monitoring"
    allow: true
  
  # Allow specific HTTP endpoints
  - spiffe_id: "spiffe://example.org/service/web"
    protocol: "http"
    method: "regex:^GET /api/v1/.*$"
    allow: true
  
  # Allow specific gRPC methods
  - spiffe_id: "spiffe://example.org/service/api"
    protocol: "grpc"
    method: "regex:^api\\..*Service/Get.*$"
    allow: true
  
  # Allow all connections matching a pattern
  - spiffe_id: "regex:spiffe://example.org/service/mesh-.*"
    allow: true
```

## 🔗 Smallstep CA Integration

PQSecure Mesh integrates with Smallstep CA for certificate management:

```bash
# Install step CLI
step ca bootstrap --ca-url https://ca.example.com:9000 --fingerprint <fingerprint>

# Generate a provisioning token
TOKEN=$(step ca token service-name --ca-url https://ca.example.com:9000)

# Configure PQSecure Mesh
export SMALLSTEP_TOKEN=$TOKEN
```

## 📊 Telemetry

PQSecure Mesh provides rich observability through structured logging and metrics:

- **Structured Logging**: Outputs detailed logs through the tracing framework
- **Environment Configuration**: Set the log level via `RUST_LOG` (e.g., `info`, `debug`)

Example logging output:
```
2025-04-07T10:15:23Z INFO pqsecure_mesh::proxy::pqc_acceptor: PQC acceptor listening on 0.0.0.0:8443
2025-04-07T10:15:30Z INFO pqsecure_mesh::telemetry: Connection successful source="192.168.1.5:52436"
2025-04-07T10:15:30Z INFO pqsecure_mesh::telemetry: Policy decision spiffe_id="spiffe://example.org/service/web" method="GET /api/v1/users" allowed=true
```

## 🛡️ Security Architecture

PQSecure Mesh implements a comprehensive security model:

1. **Endpoint Security**: All connections must present valid X.509 certificates with SPIFFE IDs
2. **Identity Verification**: SPIFFE IDs are validated against trusted domains
3. **Policy Enforcement**: Access is granted according to configured ACL policies
4. **Post-Quantum Protection**: TLS connections are secured against quantum computing threats
5. **Zero Trust Model**: Every connection is verified, regardless of network location

## 🧩 Future Expansions

- **OpenSSL PQC Integration**: Future versions will support OpenSSL's post-quantum algorithms
- **Gateway Mode**: Planned expansion to operate as an API gateway
- **Advanced Protocol Detection**: Enhanced protocol type detection
- **Enhanced Monitoring**: More detailed metrics and telemetry integration
- **Mutual Authentication Federation**: Connect across different trust domains

## 👥 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

All code should be formatted with `cargo fmt` and checked with `cargo clippy`.

## 📜 License

This project is licensed under the **Business Source License 1.1 (BSL 1.1)**. See [LICENSE](LICENSE) for full terms.

---

Built with ❤️ using Rust's powerful async ecosystem