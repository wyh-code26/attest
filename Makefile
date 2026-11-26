APP   := attest-api
CMD   := ./cmd/api
BIN   := bin/$(APP)

.PHONY: all build run test fmt fmt-fix vet ci clean deploy-tls kind-setup

all: ci build

build:
	go build -o $(BIN) $(CMD)

run: build
	./$(BIN)

test:
	go test -race -cover ./...

fmt:
	@test -z "$$(gofmt -l .)" || { echo "gofmt 需要格式化："; gofmt -l .; exit 1; }

fmt-fix:
	gofmt -w .

vet:
	go vet ./...

ci: fmt vet test

clean:
	rm -rf bin/

# 生成/复用证书，创建 attest-tls Secret，并把 caBundle 同步成同一个 CA。
# 证书轮换后只需重跑本目标，不需要重建镜像。
#
# 传入 APPLY=1 会先把 deploy/ 清单 apply 一遍再注入证书，
# 避免"先 patch 后 apply"导致 caBundle 被覆盖回空值。
#   make deploy-tls APPLY=1
deploy-tls:
	./hack/deploy-tls.sh $(if $(APPLY),--apply,)

# 创建 Kind 集群并修复 kube-proxy RBAC（缺这条绑定会导致 ClusterIP 全不通、
# admission webhook 超时）。重建 Kind 集群后必须重新执行。
kind-setup:
	./hack/kind-setup.sh
