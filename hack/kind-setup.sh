#!/usr/bin/env bash
# kind-setup.sh 创建一个可用于验证 attest 的 Kind 集群，并修掉已知的环境缺陷。
#
# 背景（真实踩过的坑）：
#   Kind 某些版本建集群时，kube-proxy 的 ServiceAccount 没有绑定
#   system:node-proxier ClusterRole，导致 kube-proxy 反复报
#   "failed to list *v1.Node: Unauthorized"，永远同步不到节点列表，
#   因此完全不生成 iptables/nftables 转发规则。
#
#   后果非常隐蔽：Pod 是 Running，Endpoints 有地址，Pod IP 也能直连，
#   但任何 Service ClusterIP 访问都超时。apiserver 调 webhook 走的正是
#   https://<svc>:443，于是 admisson webhook 报 context deadline exceeded。
#   在 failurePolicy: Fail 下，整个集群的 Pod 创建全部卡死——
#   包括用来排查问题的调试 Pod，让人没法进集群自救。
#
#   注意：这是 Kind 的本地环境缺陷，生产集群不涉及。
#        重建 Kind 集群后必须重新执行本脚本。
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-kind}"
SKIP_CREATE=0

for arg in "$@"; do
  case "$arg" in
    --skip-create) SKIP_CREATE=1 ;;
    -h|--help)
      sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

command -v kubectl >/dev/null 2>&1 || { echo "ERROR: kubectl not found in PATH" >&2; exit 1; }

# 1. 创建集群（默认名 kind，与 kubectl 默认 context kind-kind 对应）。
if [ "$SKIP_CREATE" -eq 0 ]; then
  if command -v kind >/dev/null 2>&1; then
    if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
      echo "==> Kind cluster '$CLUSTER_NAME' already exists; skipping creation"
      echo "    (pass nothing and delete it first if you want a clean rebuild)"
    else
      echo "==> Creating Kind cluster '$CLUSTER_NAME'"
      kind create cluster --name "$CLUSTER_NAME"
    fi
  else
    echo "ERROR: kind not found in PATH. Install kind, or use --skip-create against an existing cluster." >&2
    exit 1
  fi
else
  echo "==> --skip-create: using existing cluster at current kubectl context"
fi

echo "==> Current context: $(kubectl config current-context)"

# 2. 修复 kube-proxy RBAC。
#    幂等：已存在绑定时不报错（--dry-run=client | apply）。
echo "==> Ensuring kube-proxy ServiceAccount can read cluster state"
kubectl create clusterrolebinding kube-proxy-sa-fix \
  --clusterrole=system:node-proxier \
  --serviceaccount=kube-system:kube-proxy \
  --dry-run=client -o yaml | kubectl apply -f -

# 3. 让 kube-proxy 重新读取权限并重建转发规则。
#    仅改 RBAC 不重启是不够的：正在运行的 informer 已经放弃了同步，
#    必须重启 Pod 才会用新权限重新 list/watch。
echo "==> Restarting kube-proxy so it picks up the new permissions"
kubectl rollout restart ds/kube-proxy -n kube-system
kubectl rollout status ds/kube-proxy -n kube-system --timeout=180s

# 4. 自检：确认 kube-proxy 不再报 Unauthorized。
echo "==> Checking kube-proxy logs for authorization errors"
sleep 5
UNAUTH_COUNT="$(kubectl logs -n kube-system -l k8s-app=kube-proxy --tail=50 2>/dev/null | grep -c Unauthorized || true)"
if [ "${UNAUTH_COUNT:-0}" -ne 0 ]; then
  echo "ERROR: kube-proxy still logs Unauthorized ($UNAUTH_COUNT occurrences)." >&2
  echo "       ClusterIP traffic will time out and admission webhooks will fail." >&2
  kubectl logs -n kube-system -l k8s-app=kube-proxy --tail=10 >&2 || true
  exit 1
fi
echo "    no Unauthorized errors in recent kube-proxy logs"

# 5. 自检：用 kubernetes.default Service 验证 ClusterIP 转发确实恢复。
#    这是端到端证据——RBAC 看起来对了但规则没生成的情况是存在的。
echo "==> Verifying Service ClusterIP routing works"
KUBE_SVC_IP="$(kubectl get svc kubernetes -n default -o jsonpath='{.spec.clusterIP}')"
if docker exec "${CLUSTER_NAME}-control-plane" \
     curl -sk -o /dev/null -w '%{http_code}' --max-time 10 \
     "https://${KUBE_SVC_IP}/healthz" 2>/dev/null | grep -q 200; then
  echo "    ClusterIP routing OK (https://${KUBE_SVC_IP}/healthz -> 200)"
else
  echo "WARNING: could not verify ClusterIP routing via ${KUBE_SVC_IP}." >&2
  echo "         If admission webhooks time out, check kube-proxy iptables rules." >&2
fi

echo
echo "==============================================================="
echo " Kind 环境需要此修复，生产环境不涉及。"
echo " 重建集群后必须重新执行本脚本。"
echo "==============================================================="
echo
echo "Next steps:"
echo "  make deploy-tls    # 生成证书、创建 Secret、同步 caBundle"
echo "  kubectl apply -f deploy/"
