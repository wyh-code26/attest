APP   := attest-api
CMD   := ./cmd/api
BIN   := bin/$(APP)

.PHONY: all build run test fmt fmt-fix vet ci clean

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