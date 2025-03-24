.PHONY: build run test clean docker docker-up docker-down

# 默認目標
all: build

# 構建專案
build:
	cargo build --release

# 運行專案（開發模式）
run:
	cargo run

# 運行測試
test:
	cargo test

# 清理構建產物
clean:
	cargo clean
	rm -rf ./data/certs

# 構建 Docker 映像
docker:
	docker build -t pqsecure-mesh .

# 啟動 Docker Compose 環境
docker-up:
	docker-compose up -d

# 關閉 Docker Compose 環境
docker-down:
	docker-compose down

# 初始化項目目錄
init:
	mkdir -p ./data/certs
	mkdir -p ./config
	mkdir -p ./test/service-a
	mkdir -p ./test/service-b
	@if [ ! -f .env ]; then cp .env.example .env; fi
	@echo "項目目錄初始化完成！"

# 生成憑證（使用模擬 CA）
cert:
	@echo "生成測試憑證..."
	curl -X POST http://localhost:8080/api/v1/certs/request \
		-H "Content-Type: application/json" \
		-d '{"service_name": "$(SERVICE)", "namespace": "default"}'
	@echo "\n憑證生成完成，儲存在 ./data/certs/default/$(SERVICE)/"

# 顯示幫助信息
help:
	@echo "PQSecure Mesh 開發指令:"
	@echo "  make build        構建專案"
	@echo "  make run          運行專案 (開發模式)"
	@echo "  make test         運行測試"
	@echo "  make clean        清理構建產物"
	@echo "  make docker       構建 Docker 映像"
	@echo "  make docker-up    啟動 Docker Compose 環境"
	@echo "  make docker-down  關閉 Docker Compose 環境"
	@echo "  make init         初始化專案目錄"
	@echo "  make cert SERVICE=my-service  生成指定服務的憑證"