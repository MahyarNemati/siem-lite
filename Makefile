.PHONY: build test test-race test-integration bench lint fmt vet rules up down demo clean

GO ?= go
BIN := bin

build:
	CGO_ENABLED=0 $(GO) build -trimpath -o $(BIN)/siem-lite ./cmd/siem-lite
	CGO_ENABLED=0 $(GO) build -trimpath -o $(BIN)/loggen ./cmd/loggen

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

# Requires a reachable ClickHouse, e.g. `docker compose up -d clickhouse`.
test-integration:
	SIEM_TEST_CLICKHOUSE_DSN=$${SIEM_TEST_CLICKHOUSE_DSN:-clickhouse://default:@127.0.0.1:9000/default} \
		$(GO) test -tags integration -count=1 ./internal/store/...

bench:
	$(GO) test -run '^$$' -bench . -benchmem ./internal/pipeline/ ./internal/detect/

lint:
	golangci-lint run ./...

fmt:
	gofmt -w ./cmd ./internal

vet:
	$(GO) vet ./...

rules:
	$(GO) run ./cmd/siem-lite validate-rules rules

up:
	docker compose up -d --build

down:
	docker compose down

demo: build
	./$(BIN)/loggen -scenario all -once

clean:
	rm -rf $(BIN)
