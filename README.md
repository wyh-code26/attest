# attest

**在 Kubernetes 准入阶段强制执行 SLSA provenance。默认 fail closed。**

> **状态：阶段一至四完成 + 签名验证首次通电 + H1 身份判定改造。**
>
> - 阶段一至四：HTTP 骨架、TLS、Kind 端到端、真实 OCI 拉取、策略引擎、策略文件化、可观测性。
> - 签名验证（A3）：验签通过后从 bundle 的 `x509CertificateChain` **本地**提取
>   `VerifiedIdentity`，策略判定只读证书扩展，绝不信任 payload 自述字段。
> - 部署层加固：私钥不进镜像，证书由 Secret 提供，caBundle 与 Secret 原子同步。

## 部署

```bash
make kind-setup     # 创建 Kind 集群并修复 kube-proxy RBAC（仅 Kind 环境）
docker build -t attest-api:latest .
kind load docker-image attest-api:latest
kubectl apply -f deploy/
make deploy-tls     # 生成证书、创建 Secret、同步 caBundle、重启 Deployment
```

证书轮换不需要重建镜像：

```bash
./hack/deploy-tls.sh --regen
```

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
