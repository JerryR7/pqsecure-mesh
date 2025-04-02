# Contributing to PQSecure Mesh 🦀

Thank you for your interest in contributing to **PQSecure Mesh**! We welcome contributions that help improve security, performance, compatibility, or documentation.

## 🧭 Guidelines

### 1. Code Style
- Follow Rust's official style using `rustfmt`
- Use clear, secure, and documented code
- Prefer modular design – all logic should live in the appropriate `src/` modules

### 2. Pull Requests
- Create a feature branch from `main`
- Include relevant unit tests or integration tests
- Document your changes in the PR
- Reference related issues (if applicable)

### 3. Issues
- Please provide a clear title and description
- Include steps to reproduce (for bugs)
- Suggest improvements with reasoning if submitting a feature request

## 🔐 Security

If you discover a security vulnerability, **please DO NOT open an issue or pull request publicly**.  
Instead, contact us securely via:

**Email:** security@yourdomain.com

We follow a responsible disclosure process and will work with you to address the issue quickly.

## 🧪 Testing

Before submitting, ensure all tests pass:

```bash
cargo fmt --all
cargo clippy --all
cargo test --all
