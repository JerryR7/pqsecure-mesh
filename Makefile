.PHONY: build run test clean docker docker-up docker-down

# Default target
all: build

# Build the project
build:
	cargo build --release

# Run the project (development mode)
run:
	cargo run

# Run the project (controller mode)
run-controller:
	PQSM__GENERAL__MODE=controller cargo run

# Run the project (sidecar mode)
run-sidecar:
	PQSM__GENERAL__MODE=sidecar cargo run

# Run tests
test:
	cargo test

# Clean build artifacts
clean:
	cargo clean
	rm -rf ./data/certs ./data/identity

# Build Docker image
docker:
	docker build -t pqsecure-mesh .

# Start Docker Compose environment
docker-up:
	docker-compose up -d

# Stop Docker Compose environment
docker-down:
	docker-compose down

# Initialize project directories
init:
	mkdir -p ./data/certs ./data/identity
	mkdir -p ./config
	mkdir -p ./test/service-a
	mkdir -p ./test/service-b
	@if [ ! -f .env ]; then cp .env.example .env; fi
	@if [ ! -f config/policy.yaml ]; then cp config/policy.yaml.example config/policy.yaml; fi
	@echo "Project directories initialized!"

# Generate certificates (using mock CA)
cert:
	@echo "Generating test certificates..."
	curl -X POST http://localhost:8080/api/v1/identity/request \
		-H "Content-Type: application/json" \
		-d '{"service_name": "$(SERVICE)", "namespace": "default"}'
	@echo "\nCertificates generated and stored in ./data/identity/default/$(SERVICE)/"

# Display help information
help:
	@echo "PQSecure Mesh development commands:"
	@echo "  make build              Build the project"
	@echo "  make run                Run the project (development mode)"
	@echo "  make run-controller     Run the project (controller mode)"
	@echo "  make run-sidecar        Run the project (sidecar mode)"
	@echo "  make test               Run tests"
	@echo "  make clean              Clean build artifacts"
	@echo "  make docker             Build Docker image"
	@echo "  make docker-up          Start Docker Compose environment"
	@echo "  make docker-down        Stop Docker Compose environment"
	@echo "  make init               Initialize project directories"
	@echo "  make cert SERVICE=my-service  Generate certificates for the specified service"
	@echo "  make help               Display help information"

# Check code style
lint:
	cargo clippy -- -D warnings

# Format code
fmt:
	cargo fmt

# Check code coverage
coverage:
	cargo tarpaulin --out Html --output-dir ./target/coverage

# Generate documentation
doc:
	cargo doc --no-deps --open

# Create release version
release:
	@echo "Creating release version..."
	cargo build --release
	mkdir -p ./release
	cp ./target/release/pqsecure-mesh ./release/
	cp -r ./config ./release/
	tar -czvf pqsecure-mesh-release.tar.gz ./release
	@echo "Release version created: pqsecure-mesh-release.tar.gz"

# Build and push Docker image to registry
docker-push:
	@echo "Building and pushing Docker image..."
	docker build -t pqsecure-mesh:latest .
	docker tag pqsecure-mesh:latest $(REGISTRY)/pqsecure-mesh:latest
	docker push $(REGISTRY)/pqsecure-mesh:latest
	@echo "Docker image pushed to: $(REGISTRY)/pqsecure-mesh:latest"

# Create Prometheus configuration
prometheus-config:
	@echo "Creating Prometheus configuration..."
	mkdir -p ./config/prometheus
	cp ./config/prometheus.yml.example ./config/prometheus/prometheus.yml
	@echo "Prometheus configuration created: ./config/prometheus/prometheus.yml"

# Create Grafana configuration
grafana-config:
	@echo "Creating Grafana configuration..."
	mkdir -p ./config/grafana/dashboards
	mkdir -p ./config/grafana/datasources
	cp ./config/grafana-datasources.yml.example ./config/grafana/datasources/datasources.yml
	cp ./config/grafana-dashboard.json.example ./config/grafana/dashboards/pqsecure-mesh.json
	@echo "Grafana configuration created"

# Create test service pages
test-services:
	@echo "Creating test service pages..."
	mkdir -p ./test/service-a
	mkdir -p ./test/service-b
	cp ./test/service-a.html.example ./test/service-a/index.html
	cp ./test/service-b.html.example ./test/service-b/index.html
	@echo "Test service pages created"

# Install development dependencies
dev-deps:
	cargo install cargo-tarpaulin
	cargo install cargo-audit
	cargo install cargo-outdated
	@echo "Development dependencies installed"

# Perform security checks
security-check:
	cargo audit
	@echo "Security checks completed"

# Check for outdated dependencies
outdated:
	cargo outdated
	@echo "Outdated dependency check completed"