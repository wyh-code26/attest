# 构建阶段
FROM golang:1.27-alpine AS builder
WORKDIR /app

# 设置国内 Go 模块代理，并关闭校验和数据库以减少额外的网络请求
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
COPY --from=builder /app/attest-api .
COPY certs/ /app/certs/
EXPOSE 8090
CMD ["./attest-api"]