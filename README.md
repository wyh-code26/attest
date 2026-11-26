# attest

Kubernetes 准入控制器：在 Pod 创建前验证镜像的 Sigstore 签名与 SLSA provenance，
按声明式策略决定放行或拒绝。**任何一项验证失败一律拒绝，不存在降级放行。**

当前版本 `v1.0.0`：安全加固（H1/H2/H4/M1/M3）与生产部署形态（Helm Chart）
全部落地，Kind + cert-manager 全链路实测通过。

---

## 它检查什么

| 检查项 | 失败后果 |
| --- | --- |
| 镜像按 digest 固定（`@sha256:...`） | 拒绝，`must be pinned by sha256 digest` |
| registry 在白名单内 | 拒绝，且不发起任何出站请求（SSRF 防护） |
| 镜像有 attestation | 拒绝，`deny_missing_attestation` |
| attestation ≤ 4 MB | 拒绝，`deny_attestation_too_large` |
| Sigstore 完整验证链通过 | 拒绝，`deny_invalid_signature` |
| 从证书扩展推导的身份满足策略 | 拒绝，策略违规 |

**判定只读 Fulcio 证书扩展，不读 attestation payload。** payload 里的 `builder`
是推送方自己填的字符串，谁都能写成任意值，只记入审计日志（字段名 `declared_*`）；
经密码学背书的 `source_repo` / `build_signer` / `runner_env` 来自证书。

---

## 快速开始

### 部署到已有集群

```bash
# 前提：cert-manager（Chart 不内嵌为 subchart，避免 helm 需联网拉依赖）
helm repo add jetstack https://charts.jetstack.io
helm install cert-manager jetstack/cert-manager -n cert-manager --create-namespace \
  --set crds.enabled=true

helm upgrade --install attest chart/ -n attest-system --create-namespace
kubectl rollout status deploy/attest -n attest-system --timeout=180s
```

需要 Kubernetes ≥ 1.25（`chart/Chart.yaml` 的 `kubeVersion: ">=1.25.0-0"`）。
这个下限是**保守声明而非硬性 API 要求**：Chart 用到的
`admissionregistration.k8s.io/v1`（1.16 GA）、`autoscaling/v2`（1.23 GA）、
`policy/v1`（1.21 GA）都更早可用，没有依赖 1.25 之后才引入的特性。
声明 1.25 是为了避开 1.22–1.24 期间已废弃 API 的迁移窗口，
不代表 1.25 以下一定不能跑。

> 国内网络拉不到 `charts.jetstack.io` 时，可换镜像源，或先在有网环境
> `helm pull` 后离线安装。Kind 场景也可用 `hack/kind-setup.sh`，
> 它自带 cert-manager 安装与失败重试。

### 本地 Kind 环境

```bash
make kind-setup
```

一条命令走完：建集群 → 修 kube-proxy RBAC → 装 cert-manager → 构建镜像
→ 导入节点 → `helm upgrade --install`。参数见 `./hack/kind-setup.sh -h`。

### 验证准入生效

```bash
# 应被拒绝
kubectl run probe --image=alpine:3.19 --restart=Never
# Error from server: admission webhook "attest.wyh-code26.github.io" denied the request:
#   image "alpine:3.19" must be pinned by sha256 digest
```

---

## 配置

### 环境变量

服务从环境变量读配置，全部在 `internal/config/config.go` 中解析并校验。
Chart 只显式渲染下面 6 项（TLS 证书/私钥路径、策略、身份文件、信任根、
registry 白名单），其余走代码默认值；要覆盖默认值需自行在 Deployment 里加 env。

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `ATTEST_ADDR` | `:8090` | 监听地址 |
| `ATTEST_TLS_CERT` / `ATTEST_TLS_KEY` | 空 | 证书路径；由 Secret 挂载到 `/app/certs` |
| `ATTEST_TRUSTED_ROOT` | `sigstore_trusted_root.json` | 离线信任根 JSON。镜像内已内置 Sigstore 公共根 |
| `ATTEST_IDENTITY_FILE` | — | 身份 allowlist YAML |
| `ATTEST_POLICY_PATH` | — | 策略文件 |
| `ATTEST_ALLOWED_REGISTRIES` | 空（不限制） | registry host 白名单，逗号分隔。**生产必须配置** |
| `ATTEST_MAX_ATTESTATION_BYTES` | `4 << 20` | 单个 attestation layer 读取上限 |
| `ATTEST_READ_TIMEOUT` | `5s` | HTTP 读超时 |
| `ATTEST_READ_HEADER_TIMEOUT` | `2s` | 读请求头超时 |
| `ATTEST_WRITE_TIMEOUT` | `10s` | 写响应超时 |
| `ATTEST_IDLE_TIMEOUT` | `120s` | 空闲连接超时 |
| `ATTEST_SHUTDOWN_TIMEOUT` | `10s` | 优雅关闭等待 |
| `ATTEST_HANDLER_TIMEOUT` | `4s` | 单次准入处理超时 |

两个超时约束由启动校验强制：`READ_HEADER_TIMEOUT < READ_TIMEOUT`、
`HANDLER_TIMEOUT < WRITE_TIMEOUT`。违反直接启动失败，不静默接受。

### 开发模式双闸门

跳过验签需要**同时**打开两个开关，少一个都不行：

```bash
ATTEST_ALLOW_UNSIGNED=true
ATTEST_ALLOW_UNSIGNED_AND_SKIP_POLICY=true
```

设计理由：跳过验签后没有 `VerifiedIdentity`，策略无从判定。若只给一个开关，
实现上要么全拒（看起来像故障，实际是缺少身份），要么被迫写一条"空身份放行"
的隐藏分支——后者就是漏洞。两道闸门让"我在跑开发模式"成为显式且刺眼的选择。

### 策略文件

策略声明式，改它不需要重新编译。Chart 用 `checksum/config` 注解把配置哈希写进
Pod 模板，`helm upgrade` 一定触发滚动重启。

```yaml
# chart/values.yaml -> config.policy
min_slsa_level: 3
allowed_source_repositories:
  - "https://github.com/wyh-code26/attest"
allowed_build_signer_regex:
  - '^https://github\.com/wyh-code26/attest/\.github/workflows/release\.ya?ml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$'
```

策略与身份 allowlist 的**唯一生效来源是 `chart/values.yaml` 的 `config.policy`
与 `config.identities`**，由 `templates/configmap.yaml` 渲染成 ConfigMap 后以
`subPath` 覆盖镜像内同名文件。

> 策略没有第二个文件。历史上曾有 `chart/files/` 目录存放同名副本，但 Chart
> 从未引用它（改它毫无效果），已删除以免误改。要改策略请改 `values.yaml`
> 的 `config.policy`，或用 `--set-file config.policy=your-policy.yaml`。

`config.identities` 当前含一条 sigstore-js 官方 workflow 条目，**生产部署前必须
删除**——它是开发期验证链路用的。

### SLSA 等级判定

| `RunnerEnvironment` | `BuildConfigURI` | 等级 |
| --- | --- | --- |
| `github-hosted` | 非空 | L3 |
| `github-hosted` | 空 | L2 |
| `self-hosted` | 任意 | L2 |
| 空 | 非空 | L2 |
| 其他 | — | L1 |

`self-hosted` 封顶 L2：L3 要求构建过程由平台强制执行、构建方无法篡改。
自托管 runner 的环境由构建方自己控制，即使提供构建配置也无法证明其被强制执行。

---

## 生产部署形态

Chart 提供以下资源：

| 资源 | 配置 |
| --- | --- |
| `Deployment` | 3 副本，软反亲和分散到不同节点 |
| `PodDisruptionBudget` | `minAvailable: 2`（需配合 `replicas ≥ 3` 才有意义） |
| `HorizontalPodAutoscaler` | 3–10 副本，CPU 70% 触发 |
| `NetworkPolicy` ×2 | `default-deny` + 显式放行（入站 8090、DNS 53、出站 443） |
| `Certificate` ×2 | 自签 CA + webhook leaf；1 年期，提前 30 天续期，`rotationPolicy: Always` |
| `Role` | 仅 `get` 指定 Secret，不能 list/watch |
| `ServiceAccount` | `automountServiceAccountToken: false` |

`replicas` 与 `autoscaling.enabled` 互斥：开了 HPA 就要让 `replicas` 留空，
否则每次 `helm upgrade` 都会把副本数打回固定值。

### 不提供开关的安全不变量

| 不变量 | 理由 |
| --- | --- |
| `failurePolicy: Fail` | 改成 `Ignore` 意味着攻击者只要让 webhook 不可达就能绕过准入 |
| `timeoutSeconds: 10` | 调大只掩盖故障，并拖慢全集群 Pod 创建 |
| 镜像内无私钥/证书 | 构建期 `find` 扫描 `/app`，发现 `.key`/`.crt`/`.pem`/`.csr` 直接构建失败 |
| caBundle 恒为空 | 由 cainjector 通过 `cert-manager.io/inject-ca-from` 注入 |
| registry 白名单 | 空值启动时打 WARN；不配置等于允许任意 host 触发本服务出站 |

前两条不提供 values 开关是刻意的。可用性问题必须在运维层解决（多副本 + PDB +
证书续期监控），而不是在策略层让步。

### 证书轮换

```bash
kubectl delete secret attest-tls -n attest-system   # cert-manager 立即重签
```

进程在每次 TLS 握手前 `stat` 证书文件，变化即重载，**续期后无需重启 Pod**。
未用 `fsnotify`：Secret 挂载更新走 `..data` 符号链接原子替换，监听具体文件会因
inode 变化失效；`stat` 开销远小于一次 TLS 握手。重读失败时保留旧证书，避免
cert-manager 写 Secret 与 kubelet 同步挂载点之间的半写入窗口让所有握手瞬间失败。

### 为什么排除 cert-manager 命名空间

`excludeNamespaces` 默认含 `attest-system`、`cert-manager`、`kube-system`、
`kube-node-lease`。这不是疏漏，是 bootstrap 必需，因果链是一个闭环：

```
attest 的 caBundle 要靠 cert-manager 注入
  -> cert-manager 必须先装好
  -> 装 cert-manager 要创建它的 Pod
  -> 创建 Pod 被 attest 的 webhook 拦住（镜像未按 digest 固定）
  -> cert-manager 永远装不上
```

实测报错：

```
Error creating: admission webhook "attest.wyh-code26.github.io" denied the request:
image "quay.io/jetstack/cert-manager-controller:v1.16.5" must be pinned by sha256 digest
```

这个闭环**不能靠调策略解开**——cert-manager 的镜像确实没按 digest 固定，
按规则就该拒，放宽等于为了让基础设施能装而削弱准入。只能引导阶段排除。
代价是这些命名空间的 Pod 不受检查，因此**不应在其中部署业务负载**。

### 旧部署方式已弃用

`deploy/*.yaml` 与 `hack/deploy-tls.sh` 是 Chart 之前的单文件部署方式，保留用于
理解演进。**新部署不要再用**——它们是"手工同步 caBundle"故障的来源。

---

## 可观测性

### 审计日志

每次决策一行 JSON 写到 stdout：

```json
{
  "time": "2026-11-26T08:45:33Z",
  "request_id": "...",
  "namespace": "default",
  "name": "my-app",
  "image": "ghcr.io/org/app@sha256:...",
  "allowed": false,
  "reason": "signature_invalid",
  "slsa_level": 0,
  "source_repo": "https://github.com/org/repo",
  "build_signer": "https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.2.3",
  "runner_env": "github-hosted",
  "declared_builder": "https://github.com/google/cloud-build"
}
```

`source_repo` / `build_signer` / `runner_env` / `slsa_level` 来自证书，是事实；
`declared_*` 是 payload 自述，攻击者可控。两者不一致是明确的攻击信号。

结构体刻意没有 `builder` 字段：证书给的是 workflow 签名者，叫 `build_signer`
才准确。若同时存在 `builder` 与 `declared_builder`，审计时极易把自述当事实。

> 日志只写 stdout，Pod 重建即丢失。生产必须接入日志采集系统。

### 指标

`/metrics` 暴露 `attest_admission_requests_total{result}`：

| 分类 | 含义 |
| --- | --- |
| `allow` | 放行 |
| `deny_no_object` | AdmissionReview 里没有待检查对象 |
| `deny_invalid_image` | 镜像引用无法解析，或未按 digest 固定 |
| `deny_missing_attestation` | 无 attestation |
| `deny_registry_not_allowed` | registry 不在白名单 |
| `deny_attestation_too_large` | 超出 4 MB |
| `deny_invalid_signature` | 签名/证书链/SCT 失败，或 `digest_mismatch`、`identity_mismatch` |
| `deny_policy` | 身份满足签名要求，但不满足策略（SLSA/源码/签名者） |
| `deny_fetch_error` | 网络/registry 故障 |
| `error_bad_request` | 请求体不是合法 AdmissionReview |
| `error_method_not_allowed` | 非 POST |

`internal/metrics/metrics.go` 的 `allResults` 还定义了 `error_internal`，
但当前代码路径从未产生该值（属于预留）。上述 11 项是可实际观测到的分类。

`deny_registry_not_allowed` 单独分类是有意的：混进 `deny_fetch_error` 会让运维
以为 registry 抖动，而它其实是有人在尝试让本服务访问内网地址。

### 健康检查

`/healthz` 存活，`/readyz` 就绪。注意：**ClusterIP 不通时 `/readyz` 仍返回 200**，
不能作为路由健康的依据（见下方 kube-proxy 缺陷）。

---

## 开发与测试

```bash
make build      # 编译到 bin/
make ci         # fmt + vet + test -race -cover
make e2e        # 离线端到端验收
make kind-setup # Kind 本地环境
```

### 离线端到端验收

`hack/e2e/` 是主 module 下的测试包，全程不访问公网：自签一套与生产同格式的信任根
（Fulcio 链 + CT log + Rekor），签发 Sigstore bundle，推入进程内 OCI registry
（`go-containerregistry/pkg/registry` + `WithReferrersSupport`），再交给**生产**
的 `verify.SigstoreVerifier` 与 `attest.OCIFetcher`。

生产代码里没有任何"测试模式"分支，测试信任根只通过 `ATTEST_TRUSTED_ROOT` /
`ATTEST_IDENTITY_FILE` 注入。测试私钥与信任根均在 `t.TempDir()` 里实时生成，
不留任何文件在工作区（见 Design Decisions D8）。

覆盖四条 attestation 用例：

| 用例 | 断言 |
| --- | --- |
| A1 合法 | 放行，`SLSALevel=3` |
| A2 缺失 | `ErrAttestationNotFound` |
| A3 篡改一字节 | `signature invalid: accepted signatures do not match threshold` |
| A3 digest 不符 | `provided artifact digest does not match any digest in statement` |

另有三条 A6（fail closed）用例，断言「超时/故障 → 拒绝」而非「请求挂起」：

| 用例 | 断言 |
| --- | --- |
| A6 超时返回 deny | registry 永不在响应时，`300ms` 内返回 HTTP 200 + `allowed:false`，reason 含 `context deadline exceeded` |
| A6 deadline 生效 | 改 `HandlerTimeout` 为 `600ms`，返回耗时随之变化（证明是配置生效而非巧合） |
| A6 Chart 不变量 | `failurePolicy` 恒为 `Fail` 且非 `.Values` 引用；`timeoutSeconds` 无开关 |

### 项目结构

```
cmd/api/                入口：HTTP server + 证书热加载
internal/
  attest/               镜像引用解析、OCI Referrers 拉取、payload 解析
  verify/               Sigstore 验证、证书扩展 → VerifiedIdentity
  policy/               声明式策略加载与判定
  httpapi/              AdmissionReview 处理、健康检查、中间件
  audit/                结构化审计记录
  metrics/              Prometheus 指标
  config/               环境变量配置
chart/                  Helm Chart（策略写在 values.yaml 的 config.policy）
hack/
  kind-setup.sh         Kind 环境一键搭建
  e2e/                  离线端到端验收（独立 module）
docs/runbook.md         运维手册
```

---

## 验收状态

### 端到端（`make e2e`）

| 用例 | 状态 | 证据 |
| --- | --- | --- |
| A1 合法 attestation 放行 | 通过（自签信任根） | `TestE2E_A1_ValidAttestationAllowed`，`SLSALevel=3`。**生产需用真实 Sigstore 根 + 真实 Registry 复验** |
| A2 缺失 attestation 拒绝 | 通过（Kind 实测 + 自动化） | `TestE2E_A2_MissingAttestationDenied` |
| A3 篡改 payload 拒绝 | 通过 | `TestE2E_A3_TamperedPayloadDenied` |
| A3 digest 不匹配拒绝 | 通过 | `TestE2E_A3_DigestMismatchDenied` |
| A6 超时/故障 fail closed | 通过 | `TestE2E_A6_TimeoutReturnsDenyNotHang`：`300ms` 超时下返回 `allowed:false`，reason=`context deadline exceeded`；已做反向验证（注入 fail-open 后该测试变红） |
| A6 Chart 不变量 | 通过 | `TestE2E_A6_ChartFailurePolicyFail`：`failurePolicy: Fail` 为字面量，无 `.Values` 开关 |
| 镜像无测试产物 | 通过 | 构建后 `find /app -type f` 仅 `attest-api`、`sigstore_trusted_root.json`、`identities.yaml`、`policy.yaml` |

### 生产部署形态（Kind + cert-manager v1.16.5）

| 项 | 状态 | 证据 |
| --- | --- | --- |
| Chart 静态校验 | 通过 | `helm lint chart/` → `1 chart(s) linted, 0 chart(s) failed` |
| caBundle 自动注入 | 通过 | 长度 736 字符，解码 `subject=CN=attest-ca`，`notAfter=Nov 26 2027`；`openssl verify` → `OK` |
| 安全不变量不可覆盖 | 通过 | 渲染结果 `failurePolicy: Fail`、`timeoutSeconds: 10`，无 values 开关 |
| PodDisruptionBudget | 通过 | `MIN AVAILABLE 2  ALLOWED DISRUPTIONS 1` |
| HorizontalPodAutoscaler | 部分验证 | 收敛到 `currentReplicas 3 / desiredReplicas 3`。**Kind 无 metrics-server，`TARGETS <unknown>`，真实扩缩容未验证** |
| NetworkPolicy | 通过 | `attest-default-deny` + `attest-allow` |
| 镜像白名单 | 通过 | `image registry not allowed: "evil.example.com"`，不出网 |
| 证书自动重建 | 通过 | 删 Secret 后 30s 内 `READY=True` |
| 证书热加载 | 通过 | 重签后 Pod 内 serial 由 `B95A24FDC...` 变 `6459A0B9E...`，`status.startTime` 未变 |
| 准入生效 | 通过 | H4：`must be pinned by sha256 digest`；M3：`image registry not allowed` |

**已知限制**：A1 未用真实 Sigstore 根验证；HPA 真实扩缩容未在生产指标环境验证；
审计日志未内置采集与持久化。

---

## 已知环境缺陷

### Kind 的 kube-proxy RBAC

Kind 某些版本的 kube-proxy SA 缺 `system:node-proxier` 绑定：

```
kube-proxy SA 缺 system:node-proxier
  -> 反复 "failed to list *v1.Node: Unauthorized"
  -> informer 同步不到节点列表
  -> 不生成任何 iptables/nftables 转发规则
  -> 所有 Service ClusterIP 访问超时
  -> apiserver 调 https://attest-admission.attest-system.svc:443 超时
  -> admission webhook 返回 context deadline exceeded
```

这个故障极具误导性：Pod `Running`，Endpoints 有正确 IP，Pod IP 可直连，
`/readyz` 返回 200——**只有走 Service 不通**。判断依据是 `iptables -t nat` 里
查不到该 Service 的规则，且 kube-proxy 日志持续报 `Unauthorized`。

仅 Kind 环境涉及，生产集群不影响。`hack/kind-setup.sh` 会创建绑定、重启
kube-proxy，并用 `kubernetes.default` 的 ClusterIP 做自检。

### `failurePolicy: Fail` 的故障放大

webhook 不可达时全集群无法创建 Pod，**包括用来排查问题的调试 Pod**。
这是立项书 Non-negotiable 第 2 条明确选择的代价，安全上是对的。

补偿只能在运维层：保证多副本 + PDB、把 kube-proxy 与证书纳入集群初始化流程。
**不要**通过调大 `timeoutSeconds`、把 `failurePolicy` 改成 `Ignore`、或在
`namespaceSelector` 里加入救火命名空间来"解决"——那等于留了一个绕过口子。

若 `kubectl run` / `kubectl debug` 都被挡住，可用 `kubectl port-forward` 直接
验证 Pod 健康，再从集群外（`docker exec <node> curl`）测 ClusterIP，以区分
"Pod 故障"与"Service 路由故障"。

完整诊断树、紧急恢复流程、HPA/PDB 联动陷阱、常见误操作见 **`docs/runbook.md`**。

---

## Design Decisions

本章记录**为什么这样选**。立项书（v1.1）第 9 节要求「实现路径遇阻可换，关键决策写理由不写结论」，
但冻结的验收标准（第 5 节）与五条 Non-negotiable（第 4 节）不可单方面修改。
下列条目分三类：**偏离立项书并说明理由**、**立项书未覆盖的补充决策**、**明确不做并给出触发条件**。

### D1 不做 attestation 缓存（偏离立项书 7.1 / 7.3）

**立项书要求**：架构图含 Cache 组件，7.3 要求「缓存只存已验证的 attestation，接口带
`Invalidate(digest)` 和可配置 TTL，防止撤销后旧证明继续生效」。

**实际实现**：无缓存层。`internal/` 下没有 cache 包，`admission.go:180` 每个请求直接
`d.Fetcher.Fetch(ctx, image)`。

**理由**：

1. **`Invalidate(digest)` 没有事件源。** registry 不会推送「证明已撤销」的通知，
   唯一的失效手段就是 TTL 过期。这意味着所谓「防止撤销后旧证明继续生效」在工程上
   等价于「延迟一个 TTL 才失效」，而立项书设想的主动撤销不存在实现路径。
2. **当前负载下收益为负。** 准入 Webhook 的真实 QPS 通常低于 1——一个 Pod 创建
   请求拉一次 registry。缓存带来的收益远小于它引入的风险（内存无上限、缓存穿透、
   并发惊群）。
3. **缓存会放大 `failurePolicy: Fail` 的故障面。** 缓存本身成为新的单点：缓存
   实现有 bug 时，错误命中的是「放行了一个本该拒绝的镜像」，这正是 Non-negotiable
   第 2 条禁止的方向。

**重新评估的触发条件**（满足任一即应实现）：单实例准入 QPS 持续超过 10；
出现 registry 限流（HTTP 429）导致 `deny_fetch_error` 占比超过 5%。

实现时正确形态是：**LRU + 内存上限 + 只缓存「已验证通过」的结果**（拒绝结果不缓存，
避免一次误判被固化一个 TTL），TTL 默认不超过 5 分钟。

### D2 不做在线验签模式（立项书 7.3 「后置」变为「不做」）

**立项书要求**：7.3 明确「verify 包的信任根来源抽象为接口，支持三种模式：在线
（Fulcio/Rekor）、离线信任根、本地缓存 + 在线回退。**阶段二先实现离线模式，在线模式后置**」。

**实际实现**：只有离线模式 `verify.NewFileTrustMaterial(path)`。

**理由**：立项书自己在第 8 节风险表里写了「Sigstore/Rekor 在线服务在国内不可达或不稳定 →
准入验签间歇性失败，`failurePolicy: Fail` 放大为部署失败」。这条风险分析的结论是
**在线验签与 `failurePolicy: Fail` 结构性冲突**：

- 准入路径在 Pod 创建的关键路径上。在线验证失败 = 集群无法创建任何 Pod。
- 离线根的更新成本极低：Sigstore 信任根每年轮换，改一个文件并重启。
- 离线模式让 `make e2e` 完全断网可跑，这是本项目测试可复现的基础。

所以「后置」在此处的正确解读是**不做**，而不是「以后补」。立项书识别了风险却没
推导出「那就不做」，本决策把这段推理补完。

### D3 `timeoutSeconds` 是 10s，不是立项书的 5s

**立项书 A6 原文**：「测试配置 `timeoutSeconds: 5`，断言超时后拒绝而非请求挂起」。

**实际实现**：`chart/templates/validatingwebhookconfiguration.yaml:40` 为 `timeoutSeconds: 10`。

**理由**：立项书写 5s 是在阶段二设想（还没实现 registry 拉取）。现在链路是
`HandlerTimeout 4s`（`ATTEST_HANDLER_TIMEOUT` 默认值）→ 内部 ctx 到期返回 deny，
留 6s 余量给 TLS 握手、网络往返和响应串行化。若按 5s 配，正常请求会在
`HandlerTimeout` 4s 打满时被 apiserver 提前掐断，表现为「无响应」而非「收到 deny」，
反而削弱 fail closed 的确定性。

**不变的是语义**：超时 → 拒绝，而非挂起。见 `hack/e2e/a6_timeout_test.go`：
`TestE2E_A6_TimeoutReturnsDenyNotHang` 断言 300ms 超时下 200 + `allowed:false`。

### D4 信任根文件命名为 `sigstore_trusted_root.json`

生产默认信任根叫 `sigstore_trusted_root.json`，不叫 `trusted_root.json`。

**理由**：区分「真实 Sigstore 公共根」与「e2e 测试运行时现生成的自签根」。后者
历史上曾被固化成 `hack/e2e/testdata/trusted_root.json`，同名会造成误读——看文件名
分不清是生产根还是测试根，容易把测试根误部署到集群。该 fixture 已删除（见 D8）。

### D5 Chart 必须排除 `cert-manager` 命名空间

`chart/values.yaml:158` 的 `excludeNamespaces` 含 `cert-manager`，这不是省事，是修死锁：

本 Webhook 依赖 cert-manager 签发的证书才能启动。若 cert-manager 自己创建的 Pod 也要
先过本 Webhook 检查，而 `failurePolicy: Fail` 意味着 Webhook 不可用时集群拒绝创建 Pod，
就形成循环等待：**Webhook 要等 cert-manager 起来，cert-manager 要等 Webhook 放行**。

这个死锁在 Kind 实测中真实发生过，报错为
`image "quay.io/jetstack/cert-manager-controller:v1.16.5" must be pinned by sha256 digest`。

同理排除 `kube-system`、`kube-node-lease`、`attest-system`——自举路径上的组件不能
依赖被自举的对象。

### D6 不引入 `k8s.io/api`，AdmissionReview 用自定义 struct

**立项书 7.3 已定**：自定义 struct，理由「项目叙事是理解准入协议，阶段一只需极小子集」。

**现状**：仍成立。`go.mod` 直接依赖只有三个：`go-containerregistry`、`sigstore-go`、
`yaml.v3`。`k8s.io/klog/v2` 是 `sigstore-go` 的间接依赖，不是为解析 AdmissionReview 引入的。

**代价与收益**：自定义 struct 意味着 Kubernetes 升级时新增的 AdmissionReview 字段会被
静默忽略。当前只用 `uid` / `operation` / `object` / `oldObject`，都是 v1 起就稳定的字段，
风险可接受。若将来需要处理 `dryRun`、`options` 等字段，应重新评估。

### D7 策略文件热加载用 mtime 轮询，不用 fsnotify

**立项书 7.3 已定**：「policy.Loader 接口化，阶段一至三用文件加载 + mtime 轮询
（标准库），CRD/ConfigMap 后置。不引入 fsnotify」。

**现状**：`cmd/api/main.go:236` 用 `fi.ModTime()` + `fi.Size()` 比对实现热加载。
证书热加载同理由（`tls.Config.GetCertificate` + `os.Stat` 比对）。

**理由**：轮询间隔是秒级，代价可忽略；`fsnotify` 在容器内面对 ConfigMap 的
symlink 替换语义容易漏事件，引入一个第三方库换来更脆的行为不划算。

### D8 删除 `hack/e2e/testdata/trusted_root.json` fixture

历史上 `TestWriteFixture` 每次跑测试都用全新随机 PKI 覆写这个**被 git 跟踪**的文件，
后果是 `go test ./...` 每次都让工作区出现一个内容不同的变更——测试污染工作区，
且极易被误提交。

该文件**没有任何读取方**：所有 e2e 测试都在 `t.TempDir()` 里现生成信任根。
现已改为写临时目录，并删除 fixture 与 `.gitignore` 中对应例外行。

### D9 端口 8443 的文档出入

立项书架构图标注 `:8443`，实际监听 `:8090`（`ATTEST_ADDR` 默认值），
Service 443 → targetPort 8090。8443 是「看起来像 TLS 端口」的习惯写法，
实际端口对安全属性无影响。**以本文档和 `chart/values.yaml` 为准。**

### D10 A1 用自签信任根验收，而非真实 Sigstore 公共根

**立项书 A1**：「合规 Pod 被放行——集成测试：有效 SLSA L3 证明 + 白名单构建者 → allow」。

**现状**：`TestE2E_A1_ValidAttestationAllowed` 通过，但信任根是运行时自签的。

**为什么这不是缺陷**：A1 要证明的是「验证链路本身正确」——签名验证、证书扩展解析、
SLSA 等级推导、身份正则匹配全跑通。自签根完全能覆盖这些。用真实公共根能额外证明的
只有「`sigstore_trusted_root.json` 这份文件解析得对」，而这由
`TestSigstoreVerifier_RealBundle_*` 四个测试用真实 bundle 独立覆盖。

**已知限制（诚实标注）**：生产环境的 A1 仍未在真实 registry + 真实 Sigstore 根下跑过。
补验证需要联网权限与可推送的仓库地址，成本与收益需单独评估。

---

## 参考

- `docs/runbook.md` —— 运维手册（故障诊断、证书轮换、紧急恢复）
- `chart/values.yaml` —— Chart 全部可调项
- `LICENSE` —— MIT
