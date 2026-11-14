#!/usr/bin/env bash
# gen-certs.sh 生成用于 Kind 准入 Webhook 的自签 CA 和服务端证书。
set -euo pipefail

OUT_DIR="${1:-certs}"
mkdir -p "$OUT_DIR"

# 1. 生成自签 CA
openssl genrsa -out "$OUT_DIR/ca.key" 2048
openssl req -x509 -new -nodes -key "$OUT_DIR/ca.key" -sha256 -days 3650 \
  -subj "/CN=attest-ca" -out "$OUT_DIR/ca.crt"

# 2. 生成服务端私钥
openssl genrsa -out "$OUT_DIR/tls.key" 2048

# 3. 生成服务端证书签名请求 (CSR)，SAN 包含 Kind DNS 和本地调试
cat > "$OUT_DIR/csr.conf" <<EOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = attest-admission.default.svc
DNS.2 = attest-admission.default.svc.cluster.local
DNS.3 = localhost
IP.1 = 127.0.0.1
EOF

openssl req -new -key "$OUT_DIR/tls.key" -subj "/CN=attest-admission.default.svc" \
  -out "$OUT_DIR/tls.csr" -config "$OUT_DIR/csr.conf"

# 4. 用 CA 签发服务端证书
openssl x509 -req -in "$OUT_DIR/tls.csr" -CA "$OUT_DIR/ca.crt" -CAkey "$OUT_DIR/ca.key" \
  -CAcreateserial -out "$OUT_DIR/tls.crt" -days 365 -sha256 -extensions v3_req -extfile "$OUT_DIR/csr.conf"

# 5. 修复权限：私钥仅属主可读，证书公钥可读
chmod 600 "$OUT_DIR/ca.key" "$OUT_DIR/tls.key"
chmod 644 "$OUT_DIR/ca.crt" "$OUT_DIR/tls.crt"

echo "证书已生成到 $OUT_DIR/ 并已设置正确权限。"