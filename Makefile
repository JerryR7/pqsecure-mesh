.PHONY: build run clean test test-integration docker docker-compose init setup-ca cert setup-examples lint format help

# Cargo commands
CARGO := cargo
# Docker commands
DOCKER := docker
DOCKER_COMPOSE := docker compose
# Step CLI for certificates
STEP := step

# Project settings
PROJECT_NAME := pqsecure-mesh
VERSION := $(shell grep -m1 version Cargo.toml | cut -d\" -f2)
BINARY := target/release/$(PROJECT_NAME)

# Default target
.DEFAULT_GOAL := help

# Help target
help:
	@echo "PQSecure Mesh Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make build            Build the release binary"
	@echo "  make run              Run the program"
	@echo "  make test             Run unit tests"
	@echo "  make test-integration Run integration tests"
	@echo "  make docker           Build Docker image"
	@echo "  make docker-compose   Run with Docker Compose"
	@echo "  make init             Initialize project (dirs, config)"
	@echo "  make setup-ca         Setup Smallstep CA"
	@echo "  make cert             Generate test certificates"
	@echo "  make clean            Clean build artifacts"
	@echo "  make lint             Run linters"
	@echo "  make format           Format code"
	@echo ""

# Build the project
build:
	@echo "Building $(PROJECT_NAME) v$(VERSION)..."
	$(CARGO) build --release

# Run the project
run: build
	@echo "Running $(PROJECT_NAME)..."
	RUST_LOG=info ./$(BINARY)

# Run tests
test:
	@echo "Running tests..."
	$(CARGO) test

# Run integration tests
test-integration:
	@echo "Running integration tests..."
	$(CARGO) test --test '*' -- --ignored

# Build Docker image
docker:
	@echo "Building Docker image..."
	$(DOCKER) build -t $(PROJECT_NAME):$(VERSION) .
	$(DOCKER) tag $(PROJECT_NAME):$(VERSION) $(PROJECT_NAME):latest

# Start with Docker Compose
docker-compose:
	@echo "Starting with Docker Compose..."
	$(DOCKER_COMPOSE) up -d

# Initialize project directories and configuration
init:
	@echo "Initializing project..."
	mkdir -p certs config sample/html
	[ -f config/config.yaml ] || cp config/config.yaml.example config/config.yaml
	[ -f config/policy.yaml ] || cp config/policy.yaml.example config/policy.yaml

	@echo "Creating sample backend configuration..."
	echo "server { listen 8080; root /usr/share/nginx/html; }" > sample/nginx.conf
	echo "<html><body><h1>PQSecure Mesh Test Backend</h1></body></html>" > sample/html/index.html

# Setup Smallstep CA
setup-ca:
	@echo "Setting up Smallstep CA..."
	mkdir -p step
	$(DOCKER) run --rm -v $(PWD)/step:/home/step smallstep/step-ca:latest step ca init \
		--name="PQSecure Mesh CA" \
		--dns="localhost" \
		--address=":9000" \
		--provisioner="pqsecure-admin" \
		--password-file=/dev/stdin <<< "123456"
	@echo "CA setup complete. Starting CA..."
	$(DOCKER) run -d --name step-ca -p 9000:9000 -v $(PWD)/step:/home/step smallstep/step-ca:latest
	sleep 2
	$(DOCKER) exec step-ca step ca provisioner add acme --type ACME
	@echo "CA is running. Bootstrap token:"
	$(DOCKER) exec step-ca step ca token service-mesh --password 123456

# Generate test certificates
cert:
	@echo "Generating test certificates..."
	$(STEP) ca certificate "test.example.org" certs/cert.pem certs/key.pem \
		--ca-url https://localhost:9000 \
		--root step/certs/root_ca.crt \
		--not-after 24h \
		--acme \
		--force

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	$(CARGO) clean
	rm -rf target/

# Run linter
lint:
	@echo "Running linter..."
	$(CARGO) clippy -- -D warnings

# Format code
format:
	@echo "Formatting code..."
	$(CARGO) fmt

# Package release
release: build
	@echo "Creating release package..."
	mkdir -p release/$(PROJECT_NAME)-$(VERSION)
	cp $(BINARY) release/$(PROJECT_NAME)-$(VERSION)/
	cp -r config release/$(PROJECT_NAME)-$(VERSION)/
	cp README.md LICENSE release/$(PROJECT_NAME)-$(VERSION)/
	cd release && tar -czf $(PROJECT_NAME)-$(VERSION).tar.gz $(PROJECT_NAME)-$(VERSION)
	@echo "Release package created at release/$(PROJECT_NAME)-$(VERSION).tar.gz"