# Contributing to PQSecure Mesh 🦀

Thank you for your interest in contributing to **PQSecure Mesh**! We welcome contributions that help improve security, performance, compatibility, or documentation.

## 🧭 Guidelines

### 1. Code Style
- Follow Rust's official style using `rustfmt`
- Use clear, secure, and documented code
- Prefer modular design – all logic should live in the appropriate `src/` modules
- Use `thiserror` for error types and `anyhow` for results

### 2. Pull Requests
- Create a feature branch from `main`
- Include relevant unit tests or integration tests
- Document your changes in the PR
- Reference related issues (if applicable)
- Ensure all CI checks pass

### 3. Issues
- Please provide a clear title and description
- Include steps to reproduce (for bugs)
- Suggest improvements with reasoning if submitting a feature request
- Use the provided issue templates when applicable

## 🔐 Security

If you discover a security vulnerability, **please DO NOT open an issue or pull request publicly**.  
Instead, contact us securely via:

**Email:** security@example.org

We follow a responsible disclosure process and will work with you to address the issue quickly.

## 🧪 Testing

Before submitting, ensure all tests pass:

```bash
# Format code
cargo fmt --all

# Run linter
cargo clippy --all-features -- -D warnings

# Run tests
cargo test --all-features

# Run integration tests
cargo test --features integration_tests -- --ignored
```

## 📝 Project Structure

The project follows a modular architecture:

- `ca`: Certificate management with Smallstep CA
- `common`: Shared data types and utilities
- `config`: Configuration loading and validation
- `crypto`: TLS and cryptographic operations
- `identity`: SPIFFE ID validation
- `policy`: Access control policy engine
- `proxy`: Connection handling and protocol support
- `telemetry`: Logging and metrics

When adding new features, please respect this structure and follow existing patterns.

## 🚀 Development Workflow

1. Fork the repository
2. Clone your fork locally
3. Set up the development environment:
   ```
   make init
   ```
4. Create a new branch:
   ```
   git checkout -b feature/my-feature
   ```
5. Make your changes
6. Run tests and linters:
   ```
   make lint
   make test
   ```
7. Submit a pull request

## 📜 License

By contributing to PQSecure Mesh, you agree that your contributions will be licensed under the project's Business Source License (BSL). See [LICENSE](LICENSE) for details.
