# attest 运维 Runbook

本文覆盖 attest 准入服务在生产集群上的日常运维与故障处理。所有命令默认在
`attest-system` 命名空间，release 名为 `attest`。

> 所有命令都假设你已经 `kubectl config use-context <生产集群>`。
> **在执行任何 `kubectl delete` 之前先读一遍对应小节** —— 有两个操作看起来无害，
> 实际会让整个集群无法创建 Pod。

---

## 0. 快速健康检查

```bash
# 1. 副本与就绪
kubectl get deploy,pods -n attest-system

# 2. 证书是否就绪（两个都必须 True）
kubectl get certificate -n attest-system

# 3. caBundle 是否已被注入（必须非空，且能解析成证书）
kubectl get validatingwebhookconfiguration attest-admission \
  -o jsonpath='{.webhooks[0].clientConfig.caBundle}' | base64 -d \
  | openssl x509 -noout -subject -enddate

# 4. 准入是否真的在工作（应当被拒绝）
kubectl run attest-probe --image=nginx:latest --restart=Never
# 期望：image "nginx:latest" must be pinned by sha256 digest
```

四项全过 = 服务健康。

---

## 1. 故障诊断树：webhook 调用失败

几乎所有的"集群挂了"都表现为同一个症状：

```
Error from server (InternalError): Internal error occurred: failed calling webhook
"attest.wyh-code26.github.io": failed to call webhook: Post "https://attest-admission.attest-system.svc:443/admission?timeout=10s": ...
```

因为 `failurePolicy: Fail`，**只要 webhook 调不通，全集群的 Pod 创建都会被拒**——
包括你想用来排障的调试 Pod。所以先备份「紧急恢复」手段，再往下查。

### 紧急恢复（先看这个）

如果确认是 attest 自身故障且短时间修不好，用下面两种方式之一恢复集群：

**方式 A：临时放宽 failurePolicy（推荐，影响面小）**

```bash
# 记录操作人、原因、开始时间——事后必须核对并在 24h 内恢复
kubectl annotate validatingwebhookconfiguration attest-admission \
  attest.io/emergency-bypass="<你的名字> $(date -Is) 原因"

kubectl patch validatingwebhookconfiguration attest-admission \
  --type=json -p='[{"op":"replace","path":"/webhooks/0/failurePolicy","value":"Ignore"}]'
```

**放宽之后必须做的事**：
1. 在值班群/工单里同步：`attest 准入已失效，集群当前接受未验证镜像`。
2. 修好后**立即**改回，并把 `emergency-bypass` 注解删掉：
   ```bash
   kubectl patch validatingwebhookconfiguration attest-admission \
     --type=json -p='[{"op":"replace","path":"/webhooks/0/failurePolicy","value":"Fail"}]'
   kubectl annotate validatingwebhookconfiguration attest-admission \
     attest.io/emergency-bypass-
   ```
3. 复查在这一窗口内创建的 Pod 是否都合规（见第 7 节审计日志）。

> `helm upgrade` 会把这个 patch 覆盖回 `Fail`。这是有意为之：Chart 不提供
> `failurePolicy` 开关，就是为了防止有人把它当成"方便"而永久关掉。

**方式 B：整个删掉 webhook 配置**

```bash
kubectl delete validatingwebhookconfiguration attest-admission
```

只在方式 A 都执行不了（apiserver 完全不可用）时才用。删掉后准入彻底消失，
`helm upgrade` 会重新创建它。

### 逐步排查

按下面顺序查，命中即停。每一条都给出「怎么看」和「说明什么」。

#### 1.1 Endpoints 有没有地址

```bash
kubectl get endpoints attest-admission -n attest-system
```

- **`ENDPOINTS: <none>`** → 没有任何 Pod 通过 readiness。
  跳到 1.2。常见原因：Pod 起不来 / readiness 探针失败 / Service selector 不匹配。
- **有地址** → 网络路径可能有问题，看 1.3。

#### 1.2 Pod 为什么没就绪

```bash
kubectl get pods -n attest-system -o wide
kubectl describe pod -n attest-system -l app.kubernetes.io/name=attest | tail -40
kubectl logs -n attest-system -l app.kubernetes.io/name=attest --tail=50
```

按 Pod 状态对照：

| 状态 | 根因 | 处理 |
|---|---|---|
| `ContainerCreating` 长时间 | 证书 Secret 不存在，卷挂不上 | 查 `kubectl get certificate -n attest-system`，若 `READY=False` 看 `kubectl describe certificate attest-tls -n attest-system` |
| `CrashLoopBackOff` | 配置错（策略/身份文件解析失败）或端口占用 | 看日志里的 `level=ERROR`；日志第一行就写明了是 policy 还是 identities |
| `Running` 但 `READY 0/1` | readiness `/readyz` 失败 | `kubectl exec` 进去 `curl -k https://127.0.0.1:8090/readyz`；通常是配置加载失败 |
| `Pending` | 资源不足或节点选择 | `kubectl describe pod` 看 Events |
| `ImagePullBackOff` | 镜像拉不到 | 检查 `image.repository` 与 `image.pullSecrets` |

#### 1.3 Service 能否被 apiserver 访问

```bash
# 拿到 ClusterIP 与端口
kubectl get svc attest-admission -n attest-system

# 从集群内部（临时 Pod）直连
kubectl run nettest --rm -it --image=curlimages/curl:latest --restart=Never -- \
  curl -k -v --max-time 5 https://attest-admission.attest-system.svc/readyz
```

- **连不上，报 `connection refused`** → 端口对不上。Service `port: 443` 必须落到
  容器 `targetPort: 8090`。检查 Deployment 的 `containerPort` 与 `ATTEST_ADDR`。
- **连不上，报超时** → 网络策略或 kube-proxy 问题。
  - 检查本 Chart 的 NetworkPolicy 是否误挡：
    ```bash
    kubectl get networkpolicy -n attest-system -o yaml
    ```
  - **Kind 环境特有**：见 1.6。

#### 1.4 TLS / x509 报错

```
x509: certificate signed by unknown authority
x509: certificate is valid for X, not Y
```

按此表定位：

| 报错 | 根因 | 处理 |
|---|---|---|
| `unknown authority` | caBundle 与签发 leaf 的 CA 不一致 | 见 1.5 |
| `valid for <X>, not <Y>` | leaf 的 SAN 不含 `attest-admission.attest-system.svc` | 检查 `chart/templates/_helpers.tpl` 的 `attest.dnsNames`；`helm upgrade` 后 cert-manager 会重签 |
| `certificate has expired` | 证书过期且未续期 | `kubectl get certificate -n attest-system` 看 `NOT AFTER`；见第 2 节 |
| 握手成功但 webhook 报 `context deadline exceeded` | 见 1.6 |

#### 1.5 caBundle 与证书不匹配

**症状**：caBundle 非空，但 apiserver 说 `unknown authority`。

```bash
# 取三条链的指纹并比对
echo "== caBundle =="
kubectl get validatingwebhookconfiguration attest-admission \
  -o jsonpath='{.webhooks[0].clientConfig.caBundle}' | base64 -d \
  | openssl x509 -noout -subject -fingerprint -sha256

echo "== Secret 中的 leaf =="
kubectl get secret attest-tls -n attest-system -o jsonpath='{.data.tls\.crt}' \
  | base64 -d | openssl x509 -noout -subject -issuer -fingerprint -sha256

echo "== leaf 是否由 caBundle 签发 =="
kubectl get secret attest-tls -n attest-system -o jsonpath='{.data.tls\.crt}' \
  | base64 -d > /tmp/leaf.pem
kubectl get validatingwebhookconfiguration attest-admission \
  -o jsonpath='{.webhooks[0].clientConfig.caBundle}' | base64 -d > /tmp/ca.pem
openssl verify -CAfile /tmp/ca.pem /tmp/leaf.pem
```

`openssl verify` 输出 `OK` 才算匹配。

- **不匹配** → cainjector 没把 CA 注入进来，或注入了错误的 CA。
  ```bash
  kubectl logs -n cert-manager deploy/cert-manager-cainjector --tail=50
  # 检查注解是否指向正确的 Certificate
  kubectl get validatingwebhookconfiguration attest-admission \
    -o jsonpath='{.metadata.annotations.cert-manager\.io/inject-ca-from}'
  # 期望：attest-system/attest-tls
  ```
  注解对但 caBundle 不对，通常是 cainjector 卡住，`kubectl rollout restart -n cert-manager deploy/cert-manager-cainjector`。

- **注意**：`caBundle` 里应当是 **CA 证书**（`isCA: true`），不是 leaf。
  本 Chart 的 selfSigned 模式会先签一张 CA（Secret `attest-ca-tls`），
  再由这张 CA 签 webhook leaf。直接让 SelfSigned Issuer 签 leaf 是错的——
  自签 leaf 没有 `CA:TRUE`，不能作为信任锚。

#### 1.6 `context deadline exceeded`（Kind 环境专项）

**只在使用 Kind 做本地验证时会遇到，生产集群不涉及。**

根因：Kind 某些版本建集群时，kube-proxy 的 ServiceAccount 没有绑定
`system:node-proxier` 权限，kube-proxy 报 `failed to list *v1.Node: Unauthorized`，
永远同步不到节点，于是完全不生成 iptables 规则。表现是 Pod Running、Endpoints
有地址、Pod IP 能直连，但 **任何 Service ClusterIP 访问都超时**。

```bash
# 确认症状
kubectl logs -n kube-system -l k8s-app=kube-proxy --tail=20 | grep -i unauthorized
```

修复：

```bash
hack/kind-setup.sh --skip-create   # 幂等，会做 RBAC 修复 + 重启 kube-proxy + 自检
```

**重建 Kind 集群后必须重跑一次。**

---

## 2. 证书轮换

### 自动续期

Chart 配的默认值：

| 项 | 默认 | 说明 |
|---|---|---|
| `certManager.duration` | `8760h`（1 年） | 每张证书的有效期 |
| `certManager.renewBefore` | `720h`（30 天） | 到期前多久开始续期 |
| `rotationPolicy` | `Always` | 每次续期生成**新私钥**，不复用旧私钥 |

cert-manager 在剩余有效期少于 `renewBefore` 时会自动签发新证书并更新 Secret。

### 应用侧如何感知（重要）

进程**不会因为 Secret 更新而重启**。`cmd/api/main.go` 里的 `certReloader`
在每次 TLS 握手前 `stat` 证书文件，变化时重新加载，因此：

- 续期后**无需重启 Pod**，新证书在下一次握手即生效。
- 证书文件短暂损坏/半写入时**保留上一份可用证书**，不会让握手全挂。
- 只有 `tls.crt` 的修改时间/大小变化才触发重读，stat 开销可忽略。

验证热加载确实生效：

```bash
# 取一个 Pod，看当前挂载的证书
POD=$(kubectl get pods -n attest-system -l app.kubernetes.io/name=attest \
  -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n attest-system $POD -- cat /app/certs/tls.crt \
  | openssl x509 -noout -serial

# 删除 Secret 强制重签
kubectl delete secret attest-tls -n attest-system

# 等 cert-manager 重建（约 30s），再看 Pod 里的文件
kubectl get certificate attest-tls -n attest-system
kubectl exec -n attest-system $POD -- cat /app/certs/tls.crt \
  | openssl x509 -noout -serial   # 应当已经变了

# 启动时间不变，证明没有重启
kubectl get pod $POD -n attest-system -o jsonpath='{.status.startTime}{"\n"}'

# 日志里应有 reload 记录
kubectl logs -n attest-system $POD | grep "TLS certificate reloaded"
```

> **注意**：Pod 里看到新证书需要 kubelet 同步挂载点，实测约 1 分钟内完成。
> Secret 更新瞬间 Pod 内容还是旧的，这是 K8s 的机制，不是故障。

### 手动强制轮换

```bash
kubectl delete secret attest-tls -n attest-system
# cert-manager 检测到 Secret 缺失会立即重签
kubectl get certificate -n attest-system -w
```

### 轮换 CA

CA 轮换意味着所有 leaf 要重签，caBundle 也要更新。**不要**手工删 CA Secret：

```bash
# 错误做法：直接删 CA 会让现有 leaf 失去信任锚
# 正确做法：helm upgrade 改 secretName，让 cert-manager 签一套全新的
helm upgrade attest chart/ -n attest-system \
  --reuse-values \
  --set certManager.secretName=attest-tls-v2 --set certManager.caSecretName=attest-ca-tls-v2
```

新证书就绪后 cainjector 会自动更新 caBundle。确认新旧 Pod 都能正常被
apiserver 调用（滚动期间两套证书并存），再清理旧 Secret。

---

## 3. 证书来源切换：selfSigned ↔ 外部 CA

`certManager.issuerType` 有两个值。

### `selfSigned`（默认，自建 CA）

Chart 会创建两个 Issuer：

1. `attest-bootstrap`（SelfSigned）—— 只用来签 CA 证书
2. `attest-ca`（CA）—— 用上面那张 CA 签 webhook leaf

产出两个 Secret：`attest-ca-tls`（CA）和 `attest-tls`（leaf）。

**为什么需要两级**：SelfSigned Issuer 直接签出的 leaf 是自签证书，
没有 `CA:TRUE`，浏览器/Go 都拒绝把它当信任锚。必须先签一张真正的 CA。

### `ca`（接入企业 CA）

```bash
helm upgrade attest chart/ -n attest-system --reuse-values \
  --set certManager.issuerType=ca \
  --set certManager.caSecretName=corp-root-ca
```

`corp-root-ca` 必须是已存在的 `kubernetes.io/tls` 类型 Secret，且含
`tls.crt`（CA 证书）与 `tls.key`（CA 私钥）。此时 caBundle 会注入这张企业 CA。

切换前确认企业 CA 允许签发
`attest-admission.attest-system.svc` 与
`attest-admission.attest-system.svc.cluster.local` 两个 SAN。

---

## 4. HPA 与 PDB

### HPA

```bash
kubectl get hpa attest -n attest-system
kubectl describe hpa attest -n attest-system
```

`TARGETS` 显示 `<unknown>` 表示 **metrics-server 未安装或不可用**，不是 Chart 问题：

```bash
kubectl get deploy -n kube-system metrics-server
kubectl top pods -n kube-system
```

**`<unknown>` 时 HPA 仍会把副本数收敛到 `minReplicas`**，所以服务不会因为
指标缺失而掉到 0 副本。

HPA 与 `replicas` 互斥：`autoscaling.enabled=true` 时 Deployment 不渲染
`replicas` 字段，避免两边互相覆盖导致反复抖动。

### PDB

```bash
kubectl get pdb attest -n attest-system
# ALLOWED DISRUPTIONS 为 0 表示当前驱逐会违反 minAvailable，节点维护会被阻塞
```

`minAvailable: 2` + `replicas >= 3` 才能保证滚动/驱逐时至少留 2 个副本处理准入。
**如果同时把 `replicas` 降到 2，`ALLOWED DISRUPTIONS` 会变成 0，
节点 drain 会卡住**。改 `replicas` 前先检查这个数。

---

## 5. NetworkPolicy

本 Chart 创建两条策略：`attest-default-deny` 与 `attest-allow`。

- `attest-default-deny`：`podSelector: {}` + 显式 `Ingress`/`Egress`，
  拒绝本命名空间内**所有** Pod 的进出流量。
- `attest-allow`：只放行到 `targetPort` 的入站、DNS（53/UDP+TCP）与
  出站 `443`（拉取 registry 的 attestation）。

K8s 的 NetworkPolicy 是**并集语义**——任意一条放行即放行，所以必须同时有
default-deny 才是真正的默认拒绝。

常见问题：

```bash
# webhook 调不通，先看是不是策略挡住了
kubectl get networkpolicy -n attest-system -o yaml

# 出站被限，拉不到 registry
# 放行额外 CIDR：
helm upgrade attest chart/ -n attest-system --reuse-values \
  --set 'networkPolicy.allowedEgressCIDRs={10.0.0.0/8,172.16.0.0/12}'
```

> 若集群 CNI 不支持 NetworkPolicy（如 flannel 默认配置），这两条策略会被创建
> 但**不生效**。用 `kubectl get pods -n kube-system -o name | grep -i cilium`
> 之类确认 CNI。

---

## 6. RBAC

Chart 创建 `Role` + `RoleBinding`，只允许：

- `get` 名为 `attest-tls` 的 Secret（`resourceNames` 限定）
- 不能 `list`/`watch`、不能读其他 Secret

ServiceAccount 设 `automountServiceAccountToken: false`。这意味着**当前进程
无法访问 K8s API**——这是刻意的：应用不需要 K8s API，注入了反而扩大攻击面。

> Role 里的 Secret `get` 权限是为后续「从 Secret 热加载并校验证书」预留的。
> 当前证书轮换靠挂载文件 + 进程内 stat 重读实现，不走 API。
> 若确认不需要，可 `--set rbac.create=false` 彻底移除该 Role。

---

## 7. 策略更新流程

策略和身份白名单放在 ConfigMap 里，改它们**不需要重建镜像**：

策略的唯一生效来源是 `chart/values.yaml` 的 `config.policy`（及 `config.identities`）。

```bash
# 1. 改 values.yaml 的 config.policy，或用一个独立文件覆盖：
#     helm upgrade ... --set-file config.policy=my-policy.yaml
vim chart/values.yaml

# 2. 升级（Deployment 的 checksum/config 注解会触发滚动重启）
helm upgrade attest chart/ -n attest-system --reuse-values

# 3. 确认新配置已加载
kubectl get cm attest-config -n attest-system -o yaml
kubectl rollout status deploy/attest -n attest-system
kubectl logs -n attest-system deploy/attest --tail=20 | grep -i policy
```

> Chart 用 `checksum/config` 注解把 ConfigMap 内容哈希写进 Pod 模板，
> 因此改配置一定会滚动重启。没有这个注解时 `helm upgrade` 后进程仍用旧配置，
> 是极易漏掉的问题。

### 审计日志

每次准入决策都会写一行 JSON 到 stdout，含镜像、决定、原因、身份、SLSA 等级：

```bash
kubectl logs -n attest-system deploy/attest --tail=100 | jq -c 'select(.decision)'
```

确认紧急放宽期间创建的 Pod 是否合规：

```bash
# 取紧急窗口的时间范围，筛出这段时间内被 allow 的记录
kubectl logs -n attest-system deploy/attest --since=2h \
  | jq -c 'select(.decision=="allow") | {time, image, verified_identity, slsa_level}'
```

> **日志只保留在 Pod 里，Pod 重建就没了。** 生产必须把 stdout 采集到日志系统，
> 否则出了事无法回溯。这一点在 Chart 里没有实现，是有意留给你接现有日志栈的。

---

## 8. 常见误操作

| 操作 | 后果 | 替代做法 |
|---|---|---|
| 把 `failurePolicy` 改成 `Ignore` 就忘了改回来 | 准入长期失效，等于没有校验 | 用第 1 节的 patch，并同步记录 + 24h 内恢复；`helm upgrade` 会自动改回 `Fail` |
| 把 `timeoutSeconds` 调大"以解决超时" | 遮住真实根因，且 apiserver 会一直等，拖慢全集群 Pod 创建 | 查 1.6 / 1.3 的网络路径 |
| 把 `excludeNamespaces` 加上业务命名空间 | 该命名空间的 Pod 完全不受检查 | 只在 bootstrap 必需时才排除 |
| 手删 CA Secret 想触发轮换 | leaf 失去信任锚，webhook 立刻不可用 | 第 2 节"轮换 CA" |
| `replicas` 降到 2 同时又留 `pdb.minAvailable: 2` | `ALLOWED DISRUPTIONS=0`，节点 drain 卡死 | 先调 PDB 或保持 3 副本 |
| 在 `attest-system` 里跑业务负载 | 该命名空间被排除，负载不受准入检查 | 业务放独立命名空间 |

---

## 9. 环境重建

```bash
# Kind 本地环境：建集群 + 修 kube-proxy + 装 cert-manager + helm install
hack/kind-setup.sh

# 只重建 attest（集群和 cert-manager 已在）
hack/kind-setup.sh --skip-create --skip-certmanager

# 只准备环境，不部署 attest
hack/kind-setup.sh --skip-attest
```

`hack/kind-setup.sh` 里的 kube-proxy RBAC 修复**只对 Kind 成立**，
生产集群不要执行那段逻辑。

---

## 10. 设计决策索引

遇到「为什么不用缓存」「为什么超时是 10s 不是 5s」「为什么排除 cert-manager 命名空间」
这类问题时，先看 **`README.md` 的 Design Decisions 章节（D1–D10）**，不要在代码里猜。

| 编号 | 决策 | 与立项书的关系 |
| --- | --- | --- |
| D1 | 不做 attestation 缓存 | 偏离 7.1/7.3，给出重新评估的触发条件 |
| D2 | 不做在线验签模式 | 立项书 7.3「后置」明确为「不做」 |
| D3 | `timeoutSeconds` 10s（非 5s） | 偏离 A6 原文，语义不变 |
| D4 | 信任根命名 `sigstore_trusted_root.json` | 补充决策 |
| D5 | Chart 排除 `cert-manager` 命名空间 | 修真实死锁（见第 1 节） |
| D6 | 不引入 `k8s.io/api` | 遵循 7.3 |
| D7 | 策略热加载用 mtime 轮询 | 遵循 7.3 |
| D8 | 删除 testdata 信任根 fixture | 修测试污染工作区 |
| D9 | 端口 8090（非 8443） | 文档出入，以 README 为准 |
| D10 | A1 用自签信任根验收 | 已知限制，待补真实验证 |

**运维最需要知道的两条**：D1 意味着高 QPS 下直连 registry，若出现 `deny_fetch_error`
飙升应优先查 registry 限流而非怀疑缓存；D5 的 `excludeNamespaces` 不可删，删掉会重建
Bootstrap 死锁。
