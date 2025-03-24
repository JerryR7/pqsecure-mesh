FROM rust:1.70 as builder

WORKDIR /usr/src/pqsecure-mesh
COPY . .

# 安裝依賴並建構專案
RUN cargo build --release

# 使用較小的基礎映像
FROM debian:bullseye-slim

# 安裝必要的 SSL 庫和 CA 證書
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 從構建階段複製二進制檔案
COPY --from=builder /usr/src/pqsecure-mesh/target/release/pqsecure-mesh /app/
# 創建必要的目錄
RUN mkdir -p /app/data/certs

# 設定默認環境變數
ENV PQSM__GENERAL__APP_NAME="PQSecure Mesh"
ENV PQSM__GENERAL__LOG_LEVEL="info"
ENV PQSM__GENERAL__DATA_DIR="/app/data"

ENV PQSM__API__LISTEN_ADDR="0.0.0.0"
ENV PQSM__API__LISTEN_PORT="8080"
ENV PQSM__API__PATH_PREFIX="/api/v1"

ENV PQSM__PROXY__LISTEN_ADDR="0.0.0.0"
ENV PQSM__PROXY__LISTEN_PORT="9090"

ENV PQSM__CERT__ENABLE_MTLS="true"
ENV PQSM__CERT__ENABLE_PQC="true"
ENV PQSM__CERT__CA_TYPE="mock"

# 暴露 API 和 Proxy 埠
EXPOSE 8080 9090

# 執行應用程序
CMD ["/app/pqsecure-mesh"]