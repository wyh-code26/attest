#!/usr/bin/env bash
# deploy-tls.sh 把 TLS 证书同步进集群。
#
# 解决两个问题：
#   1. 证书不再打进镜像，必须由 Secret 提供。
#   2. caBundle 与服务端证书必须来自同一个 CA。
#      过去这两者靠手工同步，一旦有人重签证书却没更新 caBundle，
#      apiserver 就会报 "certificate signed by unknown authority"，
#      在 failurePolicy: Fail 下整个集群无法创建 Pod。
#      这里把"创建 Secret"和"patch caBundle"绑成一个原子动作。
#
# 用法：
#   hack/deploy-tls.sh            # 复用已有 certs/，没有则先生成
#   hack/deploy-tls.sh --regen    # 强制重新签发证书再部署
#   hack/deploy-tls.sh --apply    # 先 kubectl apply -f deploy/，再注入证书与 caBundle
#
# 注意 caBundle 的时序依赖：deploy/webhook.yaml 里 caBundle 是空的，
# 由本脚本 patch 填充。如果之后又执行了 `kubectl apply -f deploy/`，
# caBundle 会被清空，必须重新运行本脚本。--apply 参数把两者合成一步，
# 避免手工顺序出错。
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CERT_DIR="${CERT_DIR:-certs}"
NAMESPACE="${NAMESPACE:-attest-system}"
SECRET_NAME="${SECRET_NAME:-attest-tls}"
WEBHOOK_NAME="${WEBHOOK_NAME:-attest-admission}"

REGEN=0
APPLY_MANIFESTS=0
for arg in "$@"; do
  case "$arg" in
    --regen) REGEN=1 ;;
    --apply) APPLY_MANIFESTS=1 ;;
    -h|--help)
      sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

command -v kubectl >/dev/null 2>&1 || { echo "ERROR: kubectl not found in PATH" >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "ERROR: openssl not found in PATH" >&2; exit 1; }

# 1. 准备证书。没有证书，或显式要求重新签发，就跑 gen-certs.sh。
if [ "$REGEN" -eq 1 ] || [ ! -f "$CERT_DIR/tls.crt" ] || [ ! -f "$CERT_DIR/tls.key" ] || [ ! -f "$CERT_DIR/ca.crt" ]; then
  echo "==> TLS material missing or --regen requested; generating new certificates"
  bash "$REPO_ROOT/hack/gen-certs.sh" "$CERT_DIR"
else
  echo "==> Reusing existing certificates in $CERT_DIR/ (pass --regen to reissue)"
fi

# 2. 部署前先验证证书链是自洽的。
#    如果 tls.crt 不是由当前 ca.crt 签出来的，那么无论 Secret 和 caBundle
#    怎么同步，握手都会失败。这里提前拦下，避免把坏组合推上集群。
echo "==> Verifying tls.crt is signed by ca.crt"
if ! openssl verify -CAfile "$CERT_DIR/ca.crt" "$CERT_DIR/tls.crt" >/dev/null 2>&1; then
  echo "ERROR: $CERT_DIR/tls.crt is not signed by $CERT_DIR/ca.crt" >&2
  echo "       Re-run with --regen to issue a matching pair." >&2
  exit 1
fi
echo "    certificate chain OK"

# 3. 可选：先 apply 清单。必须在 patch caBundle 之前，
#    否则 apply 会把 caBundle 覆盖回 webhook.yaml 里的初始值。
if [ "$APPLY_MANIFESTS" -eq 1 ]; then
  echo "==> Applying manifests in deploy/"
  kubectl apply -f "$REPO_ROOT/deploy/"
fi

# 4. 创建/更新 Secret（幂等）。private key 权限由 kubectl 按 0400 处理。
echo "==> Applying Secret $SECRET_NAME in namespace $NAMESPACE"
kubectl create secret generic "$SECRET_NAME" -n "$NAMESPACE" \
  --from-file=tls.crt="$CERT_DIR/tls.crt" \
  --from-file=tls.key="$CERT_DIR/tls.key" \
  --from-file=ca.crt="$CERT_DIR/ca.crt" \
  --dry-run=client -o yaml | kubectl apply -f -

# 5. patch caBundle，使其与刚部署的服务端证书来自同一 CA。
#    base64 -w0 必须用单行，带换行的 base64 会被 apiserver 拒绝。
echo "==> Patching ValidatingWebhookConfiguration $WEBHOOK_NAME caBundle"
CA_BUNDLE="$(base64 -w0 < "$CERT_DIR/ca.crt")"
# 5.1 前置检查：webhook 配置必须已存在。
#     apply 过 webhook.yaml 之后 caBundle 是空串，这里要用 replace 填充；
#     如果配置不存在，patch 会失败，提示先 apply。
if ! kubectl get validatingwebhookconfiguration "$WEBHOOK_NAME" >/dev/null 2>&1; then
  echo "ERROR: ValidatingWebhookConfiguration $WEBHOOK_NAME not found." >&2
  echo "       Apply deploy/webhook.yaml first, then re-run this script." >&2
  exit 1
fi
kubectl patch validatingwebhookconfiguration "$WEBHOOK_NAME" --type=json \
  -p="[{\"op\":\"replace\",\"path\":\"/webhooks/0/clientConfig/caBundle\",\"value\":\"${CA_BUNDLE}\"}]"

# 6. 回读校验：确认集群里的 caBundle 与本地 ca.crt 指纹一致。
#    不做这一步的话，patch 静默失效（比如 API 版本变化）也看不出来。
echo "==> Verifying caBundle matches local ca.crt"
LOCAL_FP="$(openssl x509 -in "$CERT_DIR/ca.crt" -noout -fingerprint -sha256 | cut -d= -f2)"
LIVE_FP="$(kubectl get validatingwebhookconfiguration "$WEBHOOK_NAME" \
  -o jsonpath='{.webhooks[0].clientConfig.caBundle}' | base64 -d \
  | openssl x509 -noout -fingerprint -sha256 | cut -d= -f2)"
if [ "$LOCAL_FP" != "$LIVE_FP" ]; then
  echo "ERROR: caBundle fingerprint mismatch" >&2
  echo "  local: $LOCAL_FP" >&2
  echo "  live : $LIVE_FP" >&2
  exit 1
fi
echo "    caBundle OK ($LOCAL_FP)"

# 7. 重启工作负载，让新 Secret 生效。
echo "==> Restarting deployment $WEBHOOK_NAME in namespace $NAMESPACE"
kubectl rollout restart deployment/"$WEBHOOK_NAME" -n "$NAMESPACE"
kubectl rollout status deployment/"$WEBHOOK_NAME" -n "$NAMESPACE" --timeout=120s

echo
echo "TLS material deployed successfully."
echo "  Secret : $NAMESPACE/$SECRET_NAME"
echo "  caBundle: patched to match $CERT_DIR/ca.crt"
echo "  CA SHA256: $LOCAL_FP"
