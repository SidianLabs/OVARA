.PHONY: all ovara demo build vet test test-ts build-ts test-py lint check docker-build clean bench fuzz

# The product: one binary, built from proxy/ (it embeds the gateway).
GO_CORE    := runtime/gateway proxy
GO_MODULES := $(GO_CORE) services/approval services/receipt-storage services/alerting services/observability tools/cli tools/migration tools/benchmarks
TS_MODULES := sdk/typescript integrations/mcp integrations/openai policy/compiler

all: vet test build

# ── The ovara binary ─────────────────────────────────
ovara:
	cd proxy && go build -o ../ovara ./cmd/ovara
	@echo "built ./ovara — try: ./ovara demo"

demo: ovara
	./ovara demo

# ── Go ──────────────────────────────────────────────
# `set -e` + subshells: any failing module fails the target.
vet:
	@set -e; for mod in $(GO_MODULES); do echo "=== go vet $$mod ==="; (cd $$mod && go vet ./...); done

test:
	@set -e; for mod in $(GO_MODULES); do echo "=== go test $$mod ==="; (cd $$mod && go test -race -count=1 ./...); done

build:
	@set -e; for mod in $(GO_MODULES); do echo "=== go build $$mod ==="; (cd $$mod && go build ./...); done

bench:
	cd runtime/gateway && go test -run='^$$' -bench=. -benchtime=2s -benchmem ./...

# ── TypeScript / Python ─────────────────────────────
test-ts:
	@set -e; for mod in $(TS_MODULES); do echo "=== vitest $$mod ==="; (cd $$mod && npx vitest run); done

build-ts:
	@set -e; for mod in $(TS_MODULES); do echo "=== tsc $$mod ==="; (cd $$mod && npx tsc --noEmit); done

test-py:
	cd sdk/python && python -m pytest -q

# ── Lint ─────────────────────────────────────────────
lint:
	@command -v golangci-lint >/dev/null || { echo "golangci-lint is not installed"; exit 1; }
	@set -e; for mod in $(GO_MODULES); do echo "=== golangci-lint $$mod ==="; (cd $$mod && golangci-lint run ./...); done

# ── CI entry point ──────────────────────────────────
check: vet test build test-ts build-ts test-py
	@echo "=== ALL CHECKS PASSED ==="

# ── Docker ───────────────────────────────────────────
# Build context is the repo root for both images.
docker-build:
	docker build -f proxy/Dockerfile -t ovara/ovara:latest .
	docker build -f runtime/gateway/Dockerfile -t ovara/gateway:latest .

clean:
	rm -f ovara ovara.exe
	@for mod in $(TS_MODULES); do rm -rf $$mod/dist; done

# ── Fuzz (a minute each; CI runs longer weekly) ──────
fuzz:
	cd proxy && go test -run='^$$' -fuzz='^FuzzParseRefUpdates$$' -fuzztime=1m ./internal/proxy
	cd proxy && go test -run='^$$' -fuzz='^FuzzNormalizeHost$$' -fuzztime=1m ./internal/proxy
	cd runtime/gateway && go test -run='^$$' -fuzz='^FuzzMatchCanonicalResource$$' -fuzztime=1m ./internal/policy
	cd runtime/gateway && go test -run='^$$' -fuzz='^FuzzOpenNeverPanics$$' -fuzztime=1m ./internal/record
