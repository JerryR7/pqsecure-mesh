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
- **Multi-Tenant Isolation** – Full support for isolated multi-tenant deployments

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

# Initialize environment
make init

# Run in sidecar mode
PQSM__GENERAL__MODE=sidecar ./target/release/pqsecure-mesh
```

### Using Docker

```bash
# Build Docker image
docker build -t pqsecure-mesh .

# Run the container
docker run -p 8080:8080 -p 9090:9090 -e PQSM__GENERAL__MODE=sidecar pqsecure-mesh
```

### Full Environment with Docker Compose

```bash
# Start the full environment with test services
docker compose up -d
```

## 📚 Architecture

PQSecure Mesh follows **Clean Architecture** principles and a modular design:

```
pqsecure-mesh/
├── Cargo.toml                 # Project dependencies
├── src/
│   ├── common/                # Common types and error definitions
│   │   ├── mod.rs
│   │   ├── error.rs           # Error types
│   │   └── types.rs           # Common types
│   ├── config/                # Configuration management
│   │   ├── mod.rs
│   │   └── settings.rs        # Core settings
│   ├── identity/              # Identity management
│   │   ├── mod.rs
│   │   ├── provider.rs        # Identity provider interface
│   │   ├── service.rs         # Identity service implementation
│   │   ├── spiffe.rs          # SPIFFE ID support
│   │   └── types.rs           # Identity-related types
│   ├── crypto/                # Cryptographic functions
│   │   ├── mod.rs
│   │   ├── pqc.rs             # Post-quantum cryptography support
│   │   ├── tls.rs             # TLS functions
│   │   └── x509.rs            # X.509 certificate operations
│   ├── ca/                    # Certificate management
│   │   ├── mod.rs
│   │   ├── provider.rs        # CA provider interface
│   │   ├── smallstep.rs       # Smallstep CA integration
│   │   └── types.rs           # CA-related types
│   ├── policy/                # Policy engine
│   │   ├── mod.rs
│   │   ├── engine.rs          # Policy engine core
│   │   ├── store.rs           # Policy storage
│   │   └── types.rs           # Policy-related types
│   ├── proxy/                 # Proxy functions
│   │   ├── mod.rs
│   │   ├── http.rs            # HTTP proxy
│   │   ├── grpc.rs            # gRPC proxy
│   │   ├── sidecar.rs         # Sidecar management
│   │   └── types.rs           # Proxy-related types
│   ├── telemetry/             # Monitoring and logging
│   │   ├── mod.rs
│   │   ├── logging.rs         # Logging functions
│   │   └── metrics.rs         # Monitoring metrics
│   └── main.rs                # Application entry point
├── .env.example               # Environment variable example
└── README.md                  # Project documentation
```

## 📝 API Reference

### Request Identity

```bash
curl -X POST http://localhost:8080/api/v1/identity/request \
  -H "Content-Type: application/json" \
  -d '{
    "service_name": "my-service",
    "namespace": "default",
    "pqc_enabled": true
  }'
```

### Revoke Identity

```bash
curl -X POST http://localhost:8080/api/v1/identity/revoke \
  -H "Content-Type: application/json" \
  -d '{
    "spiffe_id": "spiffe://default/my-service",
    "reason": "keyCompromise"
  }'
```

### Manage Policies

```bash
# Create policy
curl -X POST http://localhost:8080/api/v1/policy \
  -H "Content-Type: application/json" \
  -d '{
    "id": "my-service-policy",
    "allow_from": [
      {"id": "spiffe://default/service-a"},
      {"id": "spiffe://default/service-b"}
    ],
    "allow_methods": [
      {"Http": ["GET", "/api/v1/resource"]},
      {"Grpc": ["my.service.Method"]}
    ]
  }'
```

## 🔗 Smallstep CA Integration

PQSecure Mesh integrates smoothly with Smallstep CA:

```bash
# Start Smallstep CA
docker run -p 9000:9000 \
  -v $PWD/step:/home/step \
  smallstep/step-ca

# Configure PQSecure Mesh
export PQSM__CERT__CA_TYPE=smallstep
export PQSM__CERT__CA_URL=https://ca.example.com
export PQSM__CERT__CA_TOKEN=your-bootstrap-token
```

## ⚙️ Policy Configuration

Access control policies are defined in YAML:

```yaml
# policy.yaml
id: web-backend
allow_from:
  - id: "spiffe://default/frontend"
  - id: "spiffe://monitoring/prometheus"
allow_methods:
  - Http: ["GET", "/api/v1/users"]
  - Http: ["POST", "/api/v1/users"]
  - Grpc: ["user.service.GetUser"]
deny_rules:
  - ip: "10.0.0.0/8"
```

## 📊 Monitoring & Metrics

PQSecure Mesh provides rich observability:

- **Prometheus Metrics**: Available at the `/metrics` endpoint
- **OpenTelemetry Tracing**: Integrates with Jaeger and other tracing systems
- **Structured Logging**: Outputs logs in structured JSON format

## 👥 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for more information.

## 📜 License

This project is licensed under the **Business Source License 1.1 (BSL 1.1)**. See [LICENSE](LICENSE) for full terms.  
Under the BSL, the code is freely available for non-production use. Production use requires a commercial license, unless the Change Date has passed.

---
