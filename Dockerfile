# 构建阶段
FROM golang:1.27-alpine AS builder
WORKDIR /app

# 配置国内 Go 模块代理，避免构建时超时
ENV GOPROXY=https://goproxy.cn,direct
ENV GOSUMDB=off

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o attest-api ./cmd/api

# 运行阶段
FROM alpine:latest
RUN apk add --no-cache ca-certificates
WORKDIR /app

# 拷贝二进制与证书
COPY --from=builder /app/attest-api .
COPY certs/ /app/certs/

# 拷贝策略配置文件（阶段三核心，缺失会导致 Fail Fast 启动失败）
COPY policy.yaml /app/policy.yaml

EXPOSE 8090
CMD ["./attest-api"]
