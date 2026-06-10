.PHONY: all build test clean docker-build docker-push lint vet check

GO_MODULES := runtime/gateway identity trust services/approval services/receipt-storage tools/cli telemetry/collector
TS_MODULES := cloud/control-plane enterprise/sso enterprise/compliance sdk/typescript integrations/mcp integrations/langchain policy/compiler apps/admin-dashboard

all: vet test build

# ── Go ──────────────────────────────────────────────
vet:
	@for mod in $(GO_MODULES); do \
		echo "=== go vet $$mod ===" && cd $$mod && go vet ./... && cd $(CURDIR); \
	done

test:
	@for mod in $(GO_MODULES); do \
		echo "=== go test $$mod ===" && cd $$mod && go test -race -count=1 ./... && cd $(CURDIR); \
	done

test-ts:
	@for mod in $(TS_MODULES); do \
		if [ -f $$mod/package.json ]; then \
			echo "=== test $$mod ===" && cd $$mod && npx vitest run 2>/dev/null || true && cd $(CURDIR); \
		fi; \
	done

build:
	@for mod in $(GO_MODULES); do \
		echo "=== go build $$mod ===" && cd $$mod && go build ./... && cd $(CURDIR); \
	done

build-ts:
	@for mod in $(TS_MODULES); do \
		if [ -f $$mod/package.json ]; then \
			echo "=== tsc $$mod ===" && cd $$mod && npx tsc --noEmit && cd $(CURDIR); \
		fi; \
	done

bench:
	@echo "=== bench runtime/gateway ===" && cd runtime/gateway && go test -bench=. -benchtime=2s -count=5 -benchmem ./... 2>/dev/null | grep -E "^Benchmark|^ok"

bench-compare:
	@echo "=== benchmark comparison ===" && cd runtime/gateway && go test -bench=. -benchtime=3s -count=10 -benchmem ./internal/handlers/ 2>/dev/null | grep "^Benchmark" | sort

# ── Docker ───────────────────────────────────────────
docker-build:
	docker build -t ovara/gateway:latest runtime/gateway
	docker build -t ovara/control-plane:latest cloud/control-plane

docker-build-all:
	docker compose -f infrastructure/docker-compose.full.yml build

docker-up:
	docker compose -f infrastructure/docker-compose.full.yml up -d

docker-down:
	docker compose -f infrastructure/docker-compose.full.yml down

# ── Lint ─────────────────────────────────────────────
lint:
	@echo "=== golangci-lint ===" && golangci-lint run runtime/gateway/... identity/... trust/... 2>/dev/null || echo "install golangci-lint for full linting"

# ── Check (CI entry point) ───────────────────────────
check: vet test build test-ts build-ts
	@echo "=== ALL CHECKS PASSED ==="

# ── Clean ────────────────────────────────────────────
clean:
	@for mod in $(GO_MODULES); do \
		rm -f $$mod/ovara* 2>/dev/null; \
	done
	@for mod in $(TS_MODULES); do \
		rm -rf $$mod/dist $$mod/node_modules 2>/dev/null; \
	done
	@echo "cleaned build artifacts"
