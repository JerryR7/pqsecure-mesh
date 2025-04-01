# PQSecure Mesh: A Zero Trust Transparent Proxy Architecture for PQC Communication

## 1. Architecture Overview

**PQSecure Mesh** is a Sidecar-based communication architecture that supports **Post-Quantum Cryptography (PQC)**, **gRPC/HTTP multi-protocol proxying**, and **Zero Trust identity verification**. It is designed to enable **secure PQC communication without requiring modifications to existing systems**.

### Mermaid Architecture Diagram

```mermaid
graph LR
    subgraph Client Side
        A[App A<br/>（No modifications required）]
        SA[Sidecar A<br/>Supports PQC TLS + Certificate]
    end

    subgraph Server Side
        B[Service B<br/>（No modifications required）]
        SB[Sidecar B<br/>Supports PQC TLS + Certificate]
    end

    A -->|Plaintext / Standard Protocol / Traditional TLS| SA
    SB -->|Plaintext / Standard Protocol / Traditional TLS| B
    SA <==>|PQC TLS（mTLS）| SB

```

---

## 2. Zero Trust Mapping Table

| Zero Trust Principle | PQSecure Mesh Implementation |
| --- | --- |
| Identity-Centric | Sidecar uses PQC certificate and mTLS mutual authentication |
| Encrypt and Verify Every Communication | All traffic between sidecars uses PQC TLS to prevent MITM and lateral movement |
| Least Privilege and Policy Control | Each sidecar can enforce ACLs and behavior policies |
| Observability and Packet Auditing | Built-in logs, metrics, and trace hooks compatible with SIEM |
| Remote Certificate Revocation and Dynamic Access Control | Supports short-lived certificates and dynamic permission updates with built-in CA |
| Prevent Lateral Movement | Each sidecar is a boundary enforcement point, requiring PQC certificate-based communication |

---

## 3. Key Management Flow (PQC Support)

### Architecture Highlights:

- CA: Recommended to use **Smallstep CA** with **SPIFFE ID**
- Certificates: Support for **Kyber**, **Dilithium** via **oqs-provider**
- Multi-tenant isolation via SPIFFE path, TTL, auto-rotation, and revocation support
- Each sidecar automatically sends CSR upon startup with endpoint metadata binding

### Sequence Flow:

```mermaid
sequenceDiagram
    participant Sidecar as Sidecar A/B
    participant CA as PQSecure CA (PQC Supported)

    Sidecar->>CA: Send CSR (including Kyber public key)
    CA-->>Sidecar: Return PQC X.509 Certificate (with SAN, SPIFFE ID)
    Sidecar->>Sidecar: Set mTLS certificate for peer authentication

```

### Mermaid Diagram: Registration, Signing, Rotation, Revocation, Multi-Tenant

```mermaid
flowchart TD
    subgraph Tenant-A
        A1[App A]
        SA[Sidecar A<br/>Cert: spiffe://tenant-a/sa]
    end

    subgraph Tenant-B
        B1[Service B]
        SB[Sidecar B<br/>Cert: spiffe://tenant-b/sb]
    end

    subgraph CA["PQSecure CA / Key Management"]
        CA1[Smallstep CA<br/>PQC + SPIFFE Support]
        CRL[CRL / OCSP Revocation Service]
        ROTATE[Key Rotation Service<br/>（Automatic Cert Rotation）]
    end

    A1 -->|Plaintext / Standard Protocol / TLS| SA
    SB -->|Plaintext / Standard Protocol / TLS| B1
    SA <==>|PQC TLS （Kyber + mTLS）| SB

    SA -- CSR with SPIFFE --> CA1
    SB -- CSR with SPIFFE --> CA1
    CA1 -- Issue PQC Cert --> SA
    CA1 -- Issue PQC Cert --> SB

    CA1 <---> CRL
    CA1 <---> ROTATE
    ROTATE -- Rotation Notice --> SA
    ROTATE -- Rotation Notice --> SB

```

### Recommended Certificate Design

- **SubjectAltName**: `spiffe://tenant-x/sidecar-y`
- **TTL**: Short-lived (e.g., 12h, 24h) to support automated rotation
- **Revocation**: OCSP and CRL supported
- **Auto-Rotation**:
    - Re-issue on each startup
    - Periodic monitoring and early renewal before expiration

---

## 4. Endpoint ACL / Policy Design

Sidecars include a built-in lightweight ACL/Policy engine supporting:

- Whitelisting by certificate ID (SPIFFE ID or SAN)
- HTTP / gRPC method control
- Namespace isolation (e.g., tenant-A / tenant-B)
- Future support for WASM-based policy plugins

### Example Policy Configuration

```yaml
id: sidecar-a
allow_from:
  - id: "spiffe://mesh/sidecar-b"
  - id: "spiffe://mesh/auditor"
allow_methods:
  - GET /status
  - POST /report

```

---

## 5. Smallstep CA Integration Architecture & Roles

**Smallstep CA** serves as the trust infrastructure for certificate registration, signing, revocation, and rotation in PQSecure Mesh. While it is not part of the core sidecar module, it is critical for secure operations.

### Integration Pattern

Module: `controller/identity`

- Defines `ICertificateAuthority` Trait
- Default Implementation: `SmallstepCAClient`

```rust
pub trait CertificateAuthority {
    fn request_certificate(&self, csr: CsrRequest) -> Result<CertificateBundle>;
    fn renew_certificate(&self, cert: Certificate) -> Result<CertificateBundle>;
    fn revoke_certificate(&self, cert_id: &str) -> Result<()>;
}

```

### Mermaid Diagram: Smallstep CA API Integration

```mermaid
flowchart TD
    SA[Sidecar A] -->|/sign| CA1[Smallstep CA]
    SA -->|/renew| CA1
    SA -->|/revoke| CA1
    CA1 -->|Certificate| SA
    CA1 --> CRL[OCSP / CRL]

    %% Module controller/identity calls Smallstep API

```

---

## 6. Use Case Scenarios

| Scenario | Description |
| --- | --- |
| Legacy Systems PQC Enablement | Wrap legacy apps with Sidecars for PQC-secured communication without changes |
| Secure IoT/OT Device Onboarding | Devices without TLS support connect via edge-side Sidecars with PQC |
| Third-party API Proxy & Isolation | Secure APIs lacking certificate auth with sidecar-based encryption and ACLs |
| Multi-tenant Service Mesh Isolation | Each tenant uses Sidecars for namespace-based isolation and certificate-based auth |

---

## 7. Extension Modules & Future Roadmap

- Modular plugins for gRPC / Kafka / REST support
- Support for PQC + Classical Hybrid TLS (NIST Standard)
- OpenTelemetry and log exporter integration
- WASM-based policy decision engine
- Integration with ZTA control plane and visualization dashboards

---
