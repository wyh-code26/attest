{{/*
命名规范。

所有资源的名字都从 fullname 派生，保证同一个 Chart 多次安装到不同 release
时不冲突。serviceName 与 secretName 例外：它们被 webhook 与 Certificate
交叉引用，必须稳定可预测，所以允许 values 覆盖。
*/}}

{{- define "attest.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "attest.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "attest.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Service 名固定为 attest-admission。

原因：ValidatingWebhookConfiguration 的 clientConfig.service.name 必须指向它，
而这个值在 webhook 被创建时就被 apiserver 记住。如果名字随 release 变化，
升级时会出现"webhook 指向旧 Service"的静默故障。
*/}}
{{- define "attest.serviceName" -}}
{{- printf "%s-admission" (include "attest.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "attest.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "attest.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "attest.labels" -}}
helm.sh/chart: {{ include "attest.chart" . }}
{{ include "attest.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: attest
{{- end -}}

{{/*
selectorLabels 一旦发布就不能再改：Deployment 的 selector 不可变，
改动会导致 helm upgrade 失败。因此这里只放最稳定的两个标签。
*/}}
{{- define "attest.selectorLabels" -}}
app.kubernetes.io/name: {{ include "attest.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
镜像引用。tag 为空时回落到 appVersion，避免渲染出 "repo:" 这种非法引用。
*/}}
{{- define "attest.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{/*
Certificate 的 DNS 名。

必须覆盖 apiserver 实际使用的访问路径：
  <svc>.<ns>.svc           —— 集群内短名
  <svc>.<ns>.svc.<domain>  —— 完整 FQDN
apiserver 调用 webhook 时用的是 FQDN，缺了它握手就报 SAN 不匹配。
*/}}
{{- define "attest.dnsNames" -}}
{{- $svc := include "attest.serviceName" . -}}
{{- $ns := .Release.Namespace -}}
{{- $domain := default "cluster.local" .Values.clusterDomain -}}
- {{ printf "%s.%s.svc" $svc $ns | quote }}
- {{ printf "%s.%s.svc.%s" $svc $ns $domain | quote }}
{{- end -}}
