.PHONY: all ovara demo build vet test test-ts build-ts test-py lint check docker-build clean bench fuzz

# The product: one binary, built from proxy/ (it embeds the gateway).
GO_CORE    := runtime/gateway proxy
GO_MODULES := $(GO_CORE) tools/cli tools/migration tools/benchmarks
TS_MODULES := sdk/typescript integrations/mcp integrations/openai

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

# ── Fuzz (FUZZTIME each, a minute by default; CI runs longer weekly) ──
# module:package:target, the same list as .github/workflows/fuzz.yml.
# `go test` runs every target's seed corpus on its own; this explores.
FUZZTIME ?= 1m
FUZZ_TARGETS := \
	proxy:./internal/proxy:FuzzParseRefUpdates \
	proxy:./internal/proxy:FuzzParseRefUpdatesRoundTrip \
	proxy:./internal/proxy:FuzzValidUploadPackRequest \
	proxy:./internal/proxy:FuzzNormalizeHost \
	proxy:./internal/proxy:FuzzReadCarriesData \
	proxy:./internal/proxy:FuzzModelValueRefusal \
	proxy:./internal/proxy:FuzzRedactPreviewCount \
	proxy:./internal/canonjson:FuzzCanonical \
	proxy:./internal/mcp:FuzzSnifferSplitInvariance \
	proxy:./internal/mcp:FuzzToolCallNameIsAlwaysGated \
	proxy:./cmd/ovara:FuzzTermSafe \
	proxy:./cmd/ovara:FuzzParseGitHubRemote \
	proxy:./internal/boxgate:FuzzPolicyLine \
	proxy:./internal/creds:FuzzScopeToRepo \
	proxy:./internal/receipts:FuzzReceiptLine \
	runtime/gateway:./internal/policy:FuzzMatchCanonicalResource \
	runtime/gateway:./internal/policy:FuzzCanonicalResource \
	runtime/gateway:./internal/policy:FuzzMatchResource \
	runtime/gateway:./internal/policy:FuzzSplitRefList \
	runtime/gateway:./internal/evaluator:FuzzPrecedence \
	runtime/gateway:./internal/record:FuzzOpenNeverPanics

fuzz:
	@set -e; for t in $(FUZZ_TARGETS); do \
		mod=$${t%%:*}; rest=$${t#*:}; pkg=$${rest%%:*}; name=$${rest#*:}; \
		echo "=== $$name ($$mod $$pkg, $(FUZZTIME))"; \
		(cd $$mod && go test -run='^$$' -fuzz="^$$name\$$" -fuzztime=$(FUZZTIME) $$pkg); \
	done
