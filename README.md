# attest

**在 Kubernetes 准入阶段强制执行 SLSA provenance。默认 fail closed。**

> **状态：阶段一至四完成 + 签名验证首次通电 + H1 身份判定改造。**
>
> - 阶段一至四：HTTP 骨架、TLS、Kind 端到端、真实 OCI 拉取、策略引擎、策略文件化、可观测性。
> - 签名验证（A3）：验签通过后从 bundle 的 `x509CertificateChain` **本地**提取
>   `VerifiedIdentity`，策略判定只读证书扩展，绝不信任 payload 自述字段。
> - 部署层加固：私钥不进镜像，证书由 Secret 提供，caBundle 与 Secret 原子同步。

## 部署

生产部署用 Helm Chart（`chart/`）。证书由 cert-manager 自动签发与轮换，
caBundle 由 cainjector 注入，**清单里恒为空**，不存在"忘了同步 caBundle"这回事。

```bash
# 前提：集群已装 cert-manager（Chart 不把它做成 subchart 依赖，避免 helm 需联网拉依赖）
helm repo add jetstack https://charts.jetstack.io
helm install cert-manager jetstack/cert-manager -n cert-manager --create-namespace \
  --set crds.enabled=true

# 部署
helm upgrade --install attest chart/ -n attest-system --create-namespace
kubectl rollout status deploy/attest -n attest-system --timeout=180s
```

本地 Kind 环境一条命令走完（建集群 → 修 kube-proxy RBAC → 装 cert-manager → helm install）：

```bash
make kind-setup
```

证书轮换不需要重建镜像，也不需要在清单里做任何操作：

```bash
kubectl delete secret attest-tls -n attest-system   # cert-manager 立即重签
```

进程在每次 TLS 握手前检查证书文件是否变化，变化即重载，**续期后无需重启 Pod**。
详见 `docs/runbook.md`。

`deploy/*.yaml` 与 `hack/deploy-tls.sh` 是 Chart 之前的单文件部署方式，
保留用于理解演进过程，**新部署不要再用**——它们是"手工同步 caBundle"故障的来源。

## Design Decisions

### 私钥不进镜像

TLS 证书通过 Secret 挂载，镜像层不包含任何私钥。轮换证书只需更新 Secret 并
patch caBundle，不需要重建镜像。

早期实现把 `certs/` 直接 `COPY` 进镜像，带来两个后果：

1. **CA 私钥泄漏**。镜像层对所有能 `pull` 该镜像的人可见。`ca.key` 一旦进层，
   任何拿到镜像的人都能签发一张被集群信任的 webhook 证书，进而冒充准入控制器。
2. **轮换成本高且易错**。换证书要重新构建、推送、重启，还得手工把新 caBundle
   同步到 webhook。两处不同步就表现为
   `x509: certificate signed by unknown authority`，在 `failurePolicy: Fail` 下
   等同于全集群无法创建 Pod。这个故障真实发生过。

现在 `Dockerfile` 在构建期用 `find` 扫描 `/app`，发现任何 `.key`/`.crt`/`.pem`/`.csr`
就直接构建失败——只靠"删掉那行 COPY"挡不住后续有人为了调试把证书拷回来。
`hack/deploy-tls.sh` 把「创建 Secret」和「patch caBundle」绑成一次原子操作，
并在部署前后各做一次校验：先确认 `tls.crt` 由 `ca.crt` 签出，再回读集群里的
caBundle 指纹与本地一致。

### Kind 环境的 kube-proxy RBAC 缺陷

Kind 某些版本建集群时 kube-proxy SA 未绑定 `system:node-proxier`，导致 ClusterIP
完全不通、admission webhook 超时。重建 Kind 后必须执行 `hack/kind-setup.sh`。

故障链条：

```
kube-proxy SA 缺 system:node-proxier
  -> 反复 "failed to list *v1.Node: Unauthorized"
  -> informer 永远同步不到节点列表
  -> 不生成任何 iptables/nftables 转发规则
  -> 所有 Service ClusterIP 访问超时
  -> apiserver 调 https://attest-admission.attest-system.svc:443 超时
  -> admission webhook 返回 context deadline exceeded
```

这个故障极具误导性：Pod 是 `Running`，Endpoints 有正确的 Pod IP，Pod IP 也能
直连，`/readyz` 一直返回 200，日志里全是正常的探活记录——**只有走 Service 才
不通**。判断依据是：`iptables -t nat` 里查不到该 Service 的规则，且 kube-proxy
日志持续报 `Unauthorized`。

这是 Kind 的本地环境缺陷，生产集群不涉及。`hack/kind-setup.sh` 会创建绑定、
重启 kube-proxy，并用 `kubernetes.default` 的 ClusterIP 做端到端自检。

### 引导顺序死锁：attest 的 webhook 会拦住 cert-manager 自己的 Pod

实测中遇到的真实现象：`helm install` 之前环境里已有一份旧的 webhook 配置，
cert-manager 三个 Deployment 全部 `0 副本`，ReplicaSet 事件是：

```
Error creating: admission webhook "attest.wyh-code26.github.io" denied the request:
image "quay.io/jetstack/cert-manager-controller:v1.16.5" must be pinned by sha256 digest
```

因果链是一个闭环：

```
attest 的 caBundle 要靠 cert-manager 注入
  -> cert-manager 必须先装好
  -> 装 cert-manager 要创建它的 Pod
  -> 创建 Pod 被 attest 的 webhook 拦住（镜像没按 digest 固定）
  -> cert-manager 永远装不上
  -> attest 的 caBundle 永远是空的
```

这个闭环不是靠调策略能解开的——**cert-manager 的镜像确实没有按 digest 固定**，
按 H4 规则就该拒绝，放宽规则等于为了让基础设施能装而削弱准入。

解法只能是引导阶段排除：`excludeNamespaces` 里必须包含 `cert-manager`。
Chart 的默认值已含该项，并写明原因，防止后来者"清理无用配置"时删掉。

代价是 `cert-manager` 命名空间的 Pod 不受检查，因此这些命名空间里不应部署业务负载。
同理 `attest-system` 自身也被排除，否则 webhook 起不来就永远无法自举。

### 证书续期后进程不会自动重载（已修）

cert-manager 更新 Secret 后，kubelet 会把新文件写进挂载点，但
`http.Server.ListenAndServeTLS(path, path)` 只在启动时读一次证书。
这意味着**证书看起来是新的（Secret 里是新的、caBundle 也对），进程却还在用启动时
那份旧证书**。等到旧证书过期，apiserver 就连不上 webhook，在 `failurePolicy: Fail`
下整个集群无法创建 Pod，而所有监控指标都显示"证书正常"。

实测证据（修复前的行为）：

```bash
# Secret 已换新
$ kubectl get secret attest-tls -n attest-system -o jsonpath='{.data.tls\.crt}' \
    | base64 -d | openssl x509 -noout -serial
serial=6459A0B9E2290E1C1041859F3E746B55

# Pod 内还是更旧的一张
$ kubectl exec -n attest-system $POD -- cat /app/certs/tls.crt | openssl x509 -noout -serial
serial=B95A24FDC70DC7975D74542C856ABC28
```

修复方式是在 `cmd/api/main.go` 里用 `tls.Config.GetCertificate` + `certReloader`：
每次握手前 `stat` 证书文件，变化则重读，**无需重启 Pod**。
未用 `fsnotify` 监听文件，是因为 Secret 挂载更新走的是 `..data` 符号链接原子替换，
监听具体文件会因 inode 变化而失效；`stat` 的开销远小于一次 TLS 握手。

重读失败时保留上一份可用证书：cert-manager 写 Secret 与 kubelet 同步挂载点之间
存在窗口，此时证书文件可能短暂处于半写入状态，让所有握手瞬间失败是不可接受的。

单测覆盖两种情形：证书被替换后必须用上新证书；文件损坏时必须保留旧证书
（`cmd/api/main_test.go`）。

### `failurePolicy: Fail` 在基础设施故障时的放大效应

kube-proxy 故障导致 apiserver 无法访问 webhook 时，整个集群的 Pod 创建被卡死，
包括用来排查问题的调试 Pod。

这是 `failurePolicy: Fail` 的真实代价，也是立项书 Non-negotiable 第 2 条明确
选择的代价：任何验证失败都必须 deny，不降级放行。安全上这是对的——降级放行意味
着攻击者只要能让 webhook 不可达，就能让任意镜像通过准入。

代价必须在运维层面补偿，而不是在策略上让步：

- **不要**通过调大 `timeoutSeconds` 或把 `failurePolicy` 改成 `Ignore` 来"解决"
  超时，那会把一个组件故障变成准入校验被静默绕过。
- **不要**在 `namespaceSelector` 里加入你的救火命名空间，那等于留了一个绕过口子。
- 正确的做法是保证 webhook 自身的高可用：多副本、PodDisruptionBudget，
  以及把基础设施依赖（kube-proxy、证书）纳入集群初始化流程。

排查此类故障时，若 `kubectl run` / `kubectl debug` 都被 webhook 挡住无法进集群，
可临时用 `kubectl port-forward` 直接验证 Pod 是否健康，再由集群外
（如 `docker exec <node> curl`）测试 ClusterIP，以区分"Pod 故障"和"Service 路由故障"。

## 验收状态

`make e2e` 一条命令跑完离线端到端验收（`hack/e2e/`）：

```bash
make e2e
```

测试链路完全离线：用 `hack/e2e/` 自签一套测试信任根（Fulcio 链 + CT log +
Rekor log），签发与生产格式一致的 Sigstore bundle，推入进程内 OCI registry
（`go-containerregistry/pkg/registry` + `WithReferrersSupport`），再交给**生产**
`verify.SigstoreVerifier` 与 `attest.OCIFetcher` 验签和取用。生产代码没有任何
"测试模式"分支，测试信任根只通过环境变量/文件注入。

| 用例 | 状态 | 证据 |
| --- | --- | --- |
| A1 合法 attestation 放行 | 通过（测试环境，自签信任根） | `TestE2E_A1_ValidAttestationAllowed`：验签成功，提取身份 `SLSALevel=3`。**生产环境需用真实 Sigstore 根在真实 Registry 上验证** |
| A2 缺失 attestation 拒绝 | 通过（Kind 实测 + e2e 自动化） | Kind 集群实测拒绝；`TestE2E_A2_MissingAttestationDenied` 返回 `ErrAttestationNotFound` |
| A3 篡改 payload 拒绝 | 通过（测试环境 + 单测，两条证据） | `TestE2E_A3_TamperedPayloadDenied`：签名后改一字节 → `signature invalid: accepted signatures do not match threshold` |
| A3 digest 不匹配拒绝 | 通过（测试环境 + 单测，两条证据） | `TestE2E_A3_DigestMismatchDenied`：签名合法但 subject digest 与镜像不符 → `provided artifact digest does not match any digest in statement` |

生产部署形态（A9）实测，全部在 Kind 集群 + 本地 cert-manager v1.16.5 上验证：

| 项 | 状态 | 证据 |
| --- | --- | --- |
| Chart 无静态校验错误 | 通过 | `helm lint chart/` → `1 chart(s) linted, 0 chart(s) failed` |
| caBundle 由 cert-manager 自动注入 | 通过 | `caBundle` 长度 736 字符（非空），解码后 `subject=CN=attest-ca`；`openssl verify -CAfile ca.pem leaf.pem` → `OK` |
| 安全不变量不被 values 覆盖 | 通过 | 渲染结果 `failurePolicy: Fail`、`timeoutSeconds: 10`；Chart 不提供这两个字段的开关 |
| PodDisruptionBudget | 通过 | `poddisruptionbudget.policy/attest  MIN AVAILABLE 2  ALLOWED DISRUPTIONS 0`（3 副本时） |
| HorizontalPodAutoscaler | 通过 | `minReplicas 3 / maxReplicas 10 / cpu 70%`；实测 `currentReplicas 3, desiredReplicas 3`。Kind 无 metrics-server，`TARGETS` 显示 `<unknown>`，但 HPA 仍正确收敛到 `minReplicas` |
| NetworkPolicy | 通过 | `attest-default-deny`（`podSelector: {}`）+ `attest-allow`（入站 8090、DNS 53、出站 443） |
| 镜像白名单（SSRF 防护） | 通过 | 白名单外仓库被直接拒绝：`image registry not allowed: "evil.example.com"`，不再发起出站请求 |
| 证书自动重建 | 通过 | 删除 Secret 后 30s 内 `certificate attest-tls READY=True`，Secret 自动重建 |
| 证书热加载（无需重启） | 通过 | 删 Secret 触发重签后，Pod 内 `tls.crt` serial 变为 `6459A0B9...`，且 `status.startTime` 未变；日志出现 `TLS certificate reloaded` |
| 准入在 Helm 部署后仍生效 | 通过 | H4：`image "alpine:3.19" must be pinned by sha256 digest`；M3：`image registry not allowed` |

测试材料边界：

- 测试信任根固化为 `hack/e2e/testdata/trusted_root.json`，随版本库提交，可复现；
  测试私钥只在测试运行时于内存中生成，不落盘、不入库（`.gitignore`）。
- `.dockerignore` 排除 `hack/`、`**/testdata/`、`certs/`、`*.key`、`*.pem`、`*.crt`，
  Dockerfile 只复制二进制与运行时配置。`TestE2E_NoTestArtifactsInImage` 静态校验
  Dockerfile 不含 `hack/` 或 `testdata` 的 `COPY`；构建后实测：

  ```bash
  $ docker run --rm --entrypoint sh attest-api:latest -c \
      "find /app -type f | grep -iE 'test|e2e'"
  /app/attest-api          # 仅匹配主程序名中的 "test"
  ```

  `/app` 实际只有 `attest-api`、`trusted_root.json`、`identities.yaml`、`policy.yaml`，
  不存在 `testdata/`、`hack/`、`certs/`。
