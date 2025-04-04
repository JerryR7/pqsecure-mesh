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