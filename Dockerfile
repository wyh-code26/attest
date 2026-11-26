# 构建阶段
FROM golang:1.27-alpine AS builder
WORKDIR /app

# 配置国内 Go 模块代理，避免构建时超时
ENV GOPROXY=https://goproxy.cn,direct

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o attest-api ./cmd/api

# 运行阶段
FROM alpine:latest
RUN apk add --no-cache ca-certificates
WORKDIR /app

# 只拷贝二进制与运行期必需的配置。
#
# 刻意不拷贝 certs/：TLS 私钥和 CA 私钥绝不能进镜像层。
# 镜像层的内容对所有能 pull 该镜像的人可见，一旦 ca.key 进层，
# 任何拿到镜像的人都能签发一张被集群信任的 webhook 证书，
# 进而冒充准入控制器或解密流量。证书改由 Secret 挂载到 /app/certs。
COPY --from=builder /app/attest-api .

# 拷贝策略、身份配置与信任根（H1 改造后强依赖）
COPY policy.yaml /app/policy.yaml
COPY identities.yaml /app/identities.yaml
COPY sigstore_trusted_root.json /app/sigstore_trusted_root.json

# 防回归自检：镜像里出现任何私钥或证书就直接构建失败。
# 光靠"删掉那一行 COPY"不够——后续有人为了调试把证书 COPY 回来，
# 或者构建上下文里混进了 certs/，都会让私钥重新进层。
# 在构建期硬失败，比事后审计镜像历史可靠得多。
RUN set -eu; \
    found="$(find /app -type f \( -name '*.key' -o -name '*.crt' -o -name '*.pem' -o -name '*.csr' -o -name 'csr.conf' -o -name '*.srl' \) 2>/dev/null || true)"; \
    if [ -n "$found" ]; then \
      echo "BUILD FAILED: image layer must not contain private keys or certificates." >&2; \
      echo "Found:" >&2; \
      echo "$found" >&2; \
      echo "TLS material must be mounted from a Secret at runtime, not baked into the image." >&2; \
      exit 1; \
    fi; \
    echo "image content check passed: no keys or certificates in the image"

EXPOSE 8090
CMD ["./attest-api"]
