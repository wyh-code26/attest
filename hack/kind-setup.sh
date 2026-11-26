#!/usr/bin/env bash
# kind-setup.sh 创建一个可用于验证 attest 的 Kind 集群，并修掉已知的环境缺陷，
# 然后安装 cert-manager，最后用 Helm 部署 attest。
#
# 背景（真实踩过的坑）：
#   Kind 某些版本建集群时，kube-proxy 的 ServiceAccount 没有绑定
#   system:node-proxier ClusterRole，导致 kube-proxy 反复报
#   "failed to list *v1.Node: Unauthorized"，永远同步不到节点列表，
#   因此完全不生成 iptables/nftables 转发规则。
#
#   后果非常隐蔽：Pod 是 Running，Endpoints 有地址，Pod IP 也能直连，
#   但任何 Service ClusterIP 访问都超时。apiserver 调 webhook 走的正是
#   https://<svc>:443，于是 admission webhook 报 context deadline exceeded。
#   在 failurePolicy: Fail 下，整个集群的 Pod 创建全部卡死——
#   包括用来排查问题的调试 Pod，让人没法进集群自救。
#
#   注意：这是 Kind 的本地环境缺陷，生产集群不涉及。
#        重建 Kind 集群后必须重新执行本脚本。
#
# 用法：
#   hack/kind-setup.sh                   # 建集群 + 修 kube-proxy + 装 cert-manager + helm install
#   hack/kind-setup.sh --skip-create     # 复用已存在集群
#   hack/kind-setup.sh --skip-certmanager# 跳过 cert-manager（已装过）
#   hack/kind-setup.sh --skip-attest     # 只准备环境，不部署 attest
#   hack/kind-setup.sh --uninstall-certmanager   # 卸载 cert-manager
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-kind}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMESPACE="${NAMESPACE:-attest-system}"
RELEASE_NAME="${RELEASE_NAME:-attest}"

# cert-manager 版本与镜像源。
# quay.io 在国内多数环境可直连；若不可达，把 CM_IMAGE_REGISTRY 换成
# 你的镜像仓库前缀（如 registry.cn-hangzhou.aliyuncs.com/jetstack-mirror），
# 脚本会按同样的路径规则预拉取并 kind load。
CM_VERSION="${CM_VERSION:-v1.16.5}"
CM_IMAGE_REGISTRY="${CM_IMAGE_REGISTRY:-quay.io/jetstack}"
CM_CHART_VERSION="${CM_CHART_VERSION:-v1.16.5}"

SKIP_CREATE=0
SKIP_CERTMANAGER=0
SKIP_ATTEST=0
UNINSTALL_CERTMANAGER=0

for arg in "$@"; do
  case "$arg" in
    --skip-create) SKIP_CREATE=1 ;;
    --skip-certmanager) SKIP_CERTMANAGER=1 ;;
    --skip-attest) SKIP_ATTEST=1 ;;
    --uninstall-certmanager) UNINSTALL_CERTMANAGER=1 ;;
    -h|--help)
      sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

command -v kubectl >/dev/null 2>&1 || { echo "ERROR: kubectl not found in PATH" >&2; exit 1; }

# 0. 可选：卸载 cert-manager。
if [ "$UNINSTALL_CERTMANAGER" -eq 1 ]; then
  echo "==> Uninstalling cert-manager (if present)"
  kubectl delete -f "https://github.com/cert-manager/cert-manager/releases/download/${CM_VERSION}/cert-manager.yaml" --ignore-not-found=true || true
  kubectl delete namespace cert-manager --ignore-not-found=true || true
  echo "    cert-manager uninstalled"
  exit 0
fi

# 1. 创建集群（默认名 kind，与 kubectl 默认 context kind-kind 对应）。
if [ "$SKIP_CREATE" -eq 0 ]; then
  if command -v kind >/dev/null 2>&1; then
    if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
      echo "==> Kind cluster '$CLUSTER_NAME' already exists; skipping creation"
      echo "    (delete it first if you want a clean rebuild)"
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

# ---------------------------------------------------------------------------
# 6. 安装 cert-manager。
#
# 为什么必须有 cert-manager：
#   Chart 里 ValidatingWebhookConfiguration 的 caBundle 恒为空，靠
#   cainjector 读 cert-manager.io/inject-ca-from 注解自动注入。
#   没有 cert-manager，caBundle 永远是空串，apiserver 调 webhook 时
#   会因为没有信任锚而 TLS 握手失败，在 failurePolicy: Fail 下
#   整个集群无法创建 Pod。它是硬前置依赖，不是可选组件。
#
# 网络处理：
#   先用 docker pull 把 4 个镜像拉到宿主，再 kind load 进节点。
#   这样做的好处是：
#     1. 镜像拉取的失败立刻可见，而不是在 Pod 里反复 ImagePullBackOff；
#     2. Kind 节点内部不需要能访问外网；
#     3. 可用 CM_IMAGE_REGISTRY 指向国内镜像源。
#   若预拉取失败，脚本会继续尝试直接 apply 官方清单（节点能联网时可行）。
# ---------------------------------------------------------------------------
install_certmanager() {
  echo "==> Installing cert-manager ${CM_VERSION}"

  if kubectl get deployment -n cert-manager cert-manager-webhook >/dev/null 2>&1; then
    echo "    cert-manager already installed; skipping (use --uninstall-certmanager to redo)"
    return 0
  fi

  local manifest="https://github.com/cert-manager/cert-manager/releases/download/${CM_VERSION}/cert-manager.yaml"
  local images=(
    "cert-manager-controller"
    "cert-manager-webhook"
    "cert-manager-cainjector"
    "cert-manager-startupapicheck"
  )

  # 6.1 预拉取镜像并加载进 Kind 节点。
  local preload_ok=1
  echo "    Pre-pulling images from ${CM_IMAGE_REGISTRY} (version ${CM_VERSION})"
  for name in "${images[@]}"; do
    local ref="${CM_IMAGE_REGISTRY}/${name}:${CM_VERSION}"
    printf '    pull %-45s ' "$ref"
    if docker pull "$ref" >/dev/null 2>&1; then
      echo "OK"
    else
      echo "FAILED"
      preload_ok=0
      break
    fi
  done

  if [ "$preload_ok" -eq 1 ]; then
    # 加载方式：docker save | docker exec ctr images import。
    #
    # 为什么不用 kind load docker-image：
    #   kind v0.30 内部执行 ctr images import --all-platforms，
    #   而 docker pull 只落当前架构的层，多架构清单里其他平台的
    #   digest 在本地不存在，于是报
    #     content digest sha256:...: not found
    #   直接 docker save | ctr import 不带 --all-platforms，规避该问题。
    #   本机 kind 版本也没有 --platform 参数可以用来限制平台。
    echo "    Loading images into Kind node(s)"
    local node
    node="$(kind get nodes --name "$CLUSTER_NAME" | head -1)"
    for name in "${images[@]}"; do
      local ref="${CM_IMAGE_REGISTRY}/${name}:${CM_VERSION}"
      # CM_IMAGE_REGISTRY 若被改成镜像站，清单里的 image 仍是 quay.io/...，
      # 需要 retag 成清单期望的名字，否则节点里找不到。
      docker tag "$ref" "quay.io/jetstack/${name}:${CM_VERSION}" 2>/dev/null || true
      if docker save "quay.io/jetstack/${name}:${CM_VERSION}" \
           | docker exec -i "$node" ctr --namespace=k8s.io images import - >/dev/null 2>&1; then
        echo "      loaded ${name}"
      else
        echo "      WARNING: image import failed for ${name}"
        preload_ok=0
      fi
    done
  fi

  if [ "$preload_ok" -eq 0 ]; then
    echo "    WARNING: pre-pull failed (no reachable ${CM_IMAGE_REGISTRY})." >&2
    echo "    NOTE: 需在可访问 quay.io 的环境执行；或设置 CM_IMAGE_REGISTRY 指向内网镜像源。" >&2
    echo "    Falling back to direct apply (requires node-level egress to quay.io)." >&2
  fi

  # 6.2 安装 CRD 与控制器。
  echo "    Applying cert-manager manifest"
  if ! kubectl apply -f "$manifest"; then
    echo "ERROR: failed to apply cert-manager manifest." >&2
    echo "       需在可访问 quay.io 的环境执行本脚本，或用 CM_IMAGE_REGISTRY 指定镜像源。" >&2
    return 1
  fi

  # 6.3 等 webhook 就绪。inject-ca-from 依赖 cainjector，而 cainjector
  #     又需要 webhook 先就绪，所以这一步必须等干净。
  echo "    Waiting for cert-manager webhook to become ready"
  kubectl wait --for=condition=Available --timeout=300s -n cert-manager deployment/cert-manager-webhook
  kubectl wait --for=condition=Available --timeout=300s -n cert-manager deployment/cert-manager-cainjector
  kubectl wait --for=condition=Available --timeout=300s -n cert-manager deployment/cert-manager

  echo "    cert-manager ready"
}

if [ "$SKIP_CERTMANAGER" -eq 0 ]; then
  install_certmanager
else
  echo "==> --skip-certmanager: assuming cert-manager is already installed"
fi

# ---------------------------------------------------------------------------
# 7. 用 Helm 部署 attest。
# ---------------------------------------------------------------------------
deploy_attest() {
  echo "==> Deploying attest via Helm into namespace ${NAMESPACE}"

  command -v helm >/dev/null 2>&1 || { echo "ERROR: helm not found in PATH" >&2; return 1; }

  # 7.1 预构建并加载 attest 镜像（Chart 默认仓库是本地 attest-api:latest）。
  if [ -f "$REPO_ROOT/Dockerfile" ] && command -v docker >/dev/null 2>&1; then
    echo "    Building image attest-api:latest"
    docker build -t attest-api:latest "$REPO_ROOT" >/dev/null
    # 与 cert-manager 镜像用同一套加载方式，理由见上面 install_certmanager()
    # 里的注释：kind load docker-image 在 kind v0.30 会因 --all-platforms
    # 报 content digest not found。这里统一走 docker save | ctr import。
    local node
    node="$(kind get nodes --name "$CLUSTER_NAME" 2>/dev/null | head -n1)"
    if [ -n "$node" ]; then
      echo "    Loading image into Kind node ${node}"
      docker save attest-api:latest \
        | docker exec -i "$node" ctr --namespace=k8s.io images import - >/dev/null
    fi
  fi

  # 7.2 Chart 渲染出的 Service 名固定为 attest-admission，
  #     webhook 引用它，不需要额外改动。
  #
  #     tolerateControlPlane=true：Kind 是单节点，control-plane 带
  #     NoSchedule 污点，不加容忍副本会一直 Pending。
  helm upgrade --install "$RELEASE_NAME" "$REPO_ROOT/chart" \
    --namespace "$NAMESPACE" \
    --create-namespace \
    --set tolerateControlPlane=true \
    --set autoscaling.enabled=false \
    --set replicas=2 \
    --set pdb.minAvailable=1 \
    --set image.repository=attest-api \
    --set image.tag=latest \
    --set image.pullPolicy=IfNotPresent \
    --wait --timeout 5m

  echo "    Waiting for deployment rollout"
  kubectl rollout status deployment/attest -n "$NAMESPACE" --timeout=180s || true
}

if [ "$SKIP_ATTEST" -eq 0 ]; then
  deploy_attest
else
  echo "==> --skip-attest: environment prepared, attest not deployed"
fi

echo
echo "==============================================================="
echo " Kind 环境需要 kube-proxy RBAC 修复，生产环境不涉及。"
echo " 重建集群后必须重新执行本脚本。"
echo "==============================================================="
echo
echo "Verify:"
echo "  kubectl get pods -n ${NAMESPACE}"
echo "  kubectl get validatingwebhookconfiguration attest-admission \\"
echo "    -o jsonpath='{.webhooks[0].clientConfig.caBundle}' | base64 -d | openssl x509 -noout -subject"
echo "  kubectl get pdb,hpa,networkpolicy -n ${NAMESPACE}"
echo
echo "Runbook: docs/runbook.md"
