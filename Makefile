# TSS development Makefile
#
# Keep ordinary targets fast and deterministic. Heavy crypto, race, stress,
# production-parameter tests, and long fuzzing are explicit opt-in targets.
# Testing policy lives in docs/testing-rules.md.

SHELL := bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

GO ?= go
GOLANGCI_LINT ?= golangci-lint
PKGS ?= ./...

# Package-level parallelism controls how many packages `go test` runs at once.
# Test-level parallelism controls how many tests marked with t.Parallel run
# concurrently within each package.
LOGICAL_CPUS := $(shell nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || echo 4)
PKG_PARALLEL ?= 8
TEST_PARALLEL ?= $(LOGICAL_CPUS)
INTEGRATION_PKG_PARALLEL ?= 4
INTEGRATION_PARALLEL ?= $(LOGICAL_CPUS)
FUZZ_PARALLEL ?= 4

UNIT_TIMEOUT ?= 1m
FAST_TIMEOUT ?= 5m
INTEGRATION_TIMEOUT ?= 20m
SECURITY_TIMEOUT ?= 30m
SLOWCRYPTO_TIMEOUT ?= 1h
RACE_TIMEOUT ?= 1h
STRESS_TIMEOUT ?= 5h

FUZZCOUNT ?= 100000x
FUZZ_SMOKE_COUNT ?= 10000x
FUZZ_NIGHTLY_COUNT ?= 1000000x

COVERPROFILE ?= coverage.out
COVERHTML ?= coverage.html

# -----------------------------------------------------------------------------
# Help
# -----------------------------------------------------------------------------

.PHONY: help
help: ## Show available targets.
	@awk 'BEGIN {FS = ":.*## "; print "TSS development targets:\n"} /^[a-zA-Z0-9_.-]+:.*## / {printf "  %-26s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# -----------------------------------------------------------------------------
# Build
# -----------------------------------------------------------------------------

.PHONY: build
build: ## Compile all packages.
	$(GO) build $(PKGS)

# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------

.PHONY: test
test: test-unit ## Alias for the default Tier 0 test suite.

.PHONY: test-unit
test-unit: ## Tier 0: fast deterministic tests; no full protocol crypto flows.
	$(GO) test -short -p $(PKG_PARALLEL) -parallel $(TEST_PARALLEL) -timeout $(UNIT_TIMEOUT) $(PKGS)

.PHONY: test-fast
test-fast: ## Tier 0 + Tier 1: fast local suite with reduced crypto fixtures.
	$(GO) test -tags='tier1' -p $(PKG_PARALLEL) -parallel $(TEST_PARALLEL) -timeout $(FAST_TIMEOUT) $(PKGS)

.PHONY: test-integration
test-integration: ## Tier 2: full protocol lifecycle tests with controlled concurrency.
	$(GO) test -tags='integration' -p $(INTEGRATION_PKG_PARALLEL) -parallel $(INTEGRATION_PARALLEL) -timeout $(INTEGRATION_TIMEOUT) $(PKGS)

.PHONY: test-security
test-security: ## Focused security-invariant packages for protocol boundary changes.
	$(GO) test -tags='integration' -p $(INTEGRATION_PKG_PARALLEL) -parallel $(INTEGRATION_PARALLEL) -timeout $(SECURITY_TIMEOUT) \
		. ./internal/wire ./frost/ed25519 ./cggmp21/secp256k1

.PHONY: test-slowcrypto
test-slowcrypto: ## Tier 3: production-parameter Paillier/ZK smoke tests.
	$(GO) test -tags='slowcrypto' -p 3 -parallel 2 -timeout $(SLOWCRYPTO_TIMEOUT) $(PKGS)

.PHONY: test-race
test-race: ## Race detector for integration-level protocol flows.
	$(GO) test -race -tags='integration' -p $(INTEGRATION_PKG_PARALLEL) -parallel $(INTEGRATION_PARALLEL) -timeout $(RACE_TIMEOUT) $(PKGS)

.PHONY: test-stress
test-stress: ## Tier 4: repeated race/stress run; explicit or scheduled only.
	$(GO) test -race -tags='integration slowcrypto stress' -p 3 -parallel 2 -count=10 -timeout $(STRESS_TIMEOUT) $(PKGS)

.PHONY: test-budget
test-budget: ## Run Tier 0+1+2 tests with runtime budget checker.
	$(GO) test -json -tags='tier1,integration' -p $(INTEGRATION_PKG_PARALLEL) -parallel $(INTEGRATION_PARALLEL) -timeout $(INTEGRATION_TIMEOUT) $(PKGS) | $(GO) run ./internal/testutil/cmd/testbudget

.PHONY: test-budget-timing
test-budget-timing: ## Print slowest integration tests with integration parallelism.
	$(GO) test -count=1 -json -tags='integration' -p $(INTEGRATION_PKG_PARALLEL) -parallel $(INTEGRATION_PARALLEL) -timeout $(INTEGRATION_TIMEOUT) ./... | \
		$(GO) run ./internal/testutil/cmd/testbudget -tier=integration -top=50 -leaves -fail=false

# -----------------------------------------------------------------------------
# Fuzzing
# -----------------------------------------------------------------------------

.PHONY: fuzz-smoke
fuzz-smoke: ## Short fuzz smoke for changed fuzz targets.
	FUZZTIME=$(FUZZ_SMOKE_COUNT) PARALLEL=$(FUZZ_PARALLEL) ./.github/scripts/fuzz-ci.sh ./...

.PHONY: fuzz-ci
fuzz-ci: ## CI-grade fuzz run; intended for dedicated fuzz jobs.
	FUZZTIME=$(FUZZCOUNT) PARALLEL=$(FUZZ_PARALLEL) ./.github/scripts/fuzz-ci.sh ./...

.PHONY: fuzz-nightly
fuzz-nightly: ## Long fuzz run for scheduled jobs.
	FUZZTIME=$(FUZZ_NIGHTLY_COUNT) PARALLEL=$(FUZZ_PARALLEL) ./.github/scripts/fuzz-ci.sh ./...

# -----------------------------------------------------------------------------
# Coverage
# -----------------------------------------------------------------------------

.PHONY: coverage-unit
coverage-unit: ## Unit coverage report for fast tests.
	$(GO) test -short -p $(PKG_PARALLEL) -parallel $(TEST_PARALLEL) -coverprofile=$(COVERPROFILE) -covermode=atomic $(PKGS)
	$(GO) tool cover -html=$(COVERPROFILE) -o $(COVERHTML)

.PHONY: coverage-security
coverage-security: ## Coverage report for security-critical packages.
	$(GO) test -tags='integration' -p $(INTEGRATION_PKG_PARALLEL) -parallel $(INTEGRATION_PARALLEL) -timeout $(SECURITY_TIMEOUT) -coverprofile=$(COVERPROFILE) -covermode=atomic \
		. ./internal/wire ./frost/ed25519 ./cggmp21/secp256k1
	$(GO) tool cover -html=$(COVERPROFILE) -o $(COVERHTML)

.PHONY: coverage-integration
coverage-integration: ## Integration coverage report; intentionally heavier than coverage-unit.
	$(GO) test -tags='integration' -p $(INTEGRATION_PKG_PARALLEL) -parallel $(INTEGRATION_PARALLEL) -timeout $(INTEGRATION_TIMEOUT) -coverprofile=$(COVERPROFILE) -covermode=atomic $(PKGS)
	$(GO) tool cover -html=$(COVERPROFILE) -o $(COVERHTML)

.PHONY: coverage-heavy
coverage-heavy: ## Heavy combined coverage; slow and explicit only.
	$(GO) test -tags='integration slowcrypto' -race -p 1 -parallel 1 -timeout $(STRESS_TIMEOUT) -coverprofile=$(COVERPROFILE) -covermode=atomic $(PKGS)
	$(GO) tool cover -html=$(COVERPROFILE) -o $(COVERHTML)

.PHONY: coverage-check
coverage-check: ## Enforce per-area coverage thresholds; exits non-zero on violation.
	@echo "=== coverage-check: per-area threshold enforcement ==="
	@$(GO) test -short -coverprofile=/tmp/cov_unit.out -covermode=atomic ./internal/wire ./internal/wire/... 2>/dev/null; \
	WIRE_COV=$$($(GO) tool cover -func=/tmp/cov_unit.out 2>/dev/null | awk '/total:/ {print $$3}' | tr -d '%'); \
	echo "internal/wire: $$WIRE_COV% (threshold 78%)"; \
	if [ "$$(echo "$$WIRE_COV < 78" | bc -l 2>/dev/null || echo 0)" = "1" ]; then echo "FAIL: internal/wire coverage $$WIRE_COV% below 78%"; exit 1; fi
	@$(GO) test -short -coverprofile=/tmp/cov_root.out -covermode=atomic . 2>/dev/null; \
	ROOT_COV=$$($(GO) tool cover -func=/tmp/cov_root.out 2>/dev/null | awk '/total:/ {print $$3}' | tr -d '%'); \
	echo "tss (root):     $$ROOT_COV% (threshold 75%)"; \
	if [ "$$(echo "$$ROOT_COV < 75" | bc -l 2>/dev/null || echo 0)" = "1" ]; then echo "FAIL: root package coverage $$ROOT_COV% below 75%"; exit 1; fi
	@$(GO) test -short -coverprofile=/tmp/cov_frost.out -covermode=atomic ./frost/ed25519 2>/dev/null; \
	FROST_COV=$$($(GO) tool cover -func=/tmp/cov_frost.out 2>/dev/null | awk '/total:/ {print $$3}' | tr -d '%'); \
	echo "frost/ed25519:  $$FROST_COV% (threshold 73%)"; \
	if [ "$$(echo "$$FROST_COV < 73" | bc -l 2>/dev/null || echo 0)" = "1" ]; then echo "FAIL: frost/ed25519 coverage $$FROST_COV% below 73%"; exit 1; fi
	@$(GO) test -short -coverprofile=/tmp/cov_shamir.out -covermode=atomic ./internal/shamir 2>/dev/null; \
	SHAMIR_COV=$$($(GO) tool cover -func=/tmp/cov_shamir.out 2>/dev/null | awk '/total:/ {print $$3}' | tr -d '%'); \
	echo "internal/shamir: $$SHAMIR_COV% (threshold 90%)"; \
	if [ "$$(echo "$$SHAMIR_COV < 90" | bc -l 2>/dev/null || echo 0)" = "1" ]; then echo "FAIL: internal/shamir coverage $$SHAMIR_COV% below 90%"; exit 1; fi
	@$(GO) test -short -coverprofile=/tmp/cov_secret.out -covermode=atomic ./internal/secret 2>/dev/null; \
	SECRET_COV=$$($(GO) tool cover -func=/tmp/cov_secret.out 2>/dev/null | awk '/total:/ {print $$3}' | tr -d '%'); \
	echo "internal/secret: $$SECRET_COV% (threshold 75%)"; \
	if [ "$$(echo "$$SECRET_COV < 75" | bc -l 2>/dev/null || echo 0)" = "1" ]; then echo "FAIL: internal/secret coverage $$SECRET_COV% below 75%"; exit 1; fi
	@echo "=== coverage-check: all thresholds passed ==="

# -----------------------------------------------------------------------------
# Benchmarks
# -----------------------------------------------------------------------------

BENCHTIME ?= 10s
BENCHCOUNT ?= 1
BENCH_PARALLEL ?= $(LOGICAL_CPUS)
BENCH_TIMEOUT ?= 1h

.PHONY: bench
bench: ## Run integration-level benchmarks
	$(GO) test -bench=. -benchtime=$(BENCHTIME) -count=$(BENCHCOUNT) -parallel=$(BENCH_PARALLEL) -timeout $(BENCH_TIMEOUT) -tags='tier1 integration' ./...

# -----------------------------------------------------------------------------
# Golden files & test vectors
# -----------------------------------------------------------------------------

GOLDEN_TIMEOUT ?= 30m

.PHONY: golden-update
golden-update: ## Regenerate all binary wire-format golden vectors.
	UPDATE_GOLDEN=1 $(GO) test -run 'TestGolden' -count=1 -timeout $(GOLDEN_TIMEOUT) . ./frost/ed25519 ./internal/zk/paillier ./internal/zk/schnorr
	UPDATE_GOLDEN=1 $(GO) test -run 'TestFast_Golden' -count=1 -timeout $(GOLDEN_TIMEOUT) ./cggmp21/secp256k1
	UPDATE_GOLDEN=1 $(GO) test -run 'TestGolden' -tags='integration' -count=1 -timeout $(GOLDEN_TIMEOUT) ./cggmp21/secp256k1

.PHONY: golden-update-protocol
golden-update-protocol: ## Regenerate JSON protocol cross-implementation vectors.
	$(GO) test -run 'TestGenerateVectors$$' -tags='vectorgen' -count=1 -timeout $(GOLDEN_TIMEOUT) ./frost/ed25519 ./cggmp21/secp256k1

.PHONY: golden-update-all
golden-update-all: golden-update golden-update-protocol ## Regenerate all golden and protocol vectors.

.PHONY: golden-verify
golden-verify: ## Verify binary golden vectors match current wire format.
	$(GO) test -run 'TestGolden' -count=1 -timeout $(GOLDEN_TIMEOUT) ./...
	$(GO) test -run 'TestGolden' -tags='integration' -count=1 -timeout $(GOLDEN_TIMEOUT) ./cggmp21/secp256k1

.PHONY: golden-verify-protocol
golden-verify-protocol: ## Verify JSON protocol vectors against library implementation.
	$(GO) test -run 'CrossImplementation' -count=1 -timeout $(GOLDEN_TIMEOUT) ./frost/ed25519
	$(GO) test -run 'CrossImplementation' -tags='integration' -count=1 -timeout $(GOLDEN_TIMEOUT) ./cggmp21/secp256k1

.PHONY: golden-verify-all
golden-verify-all: golden-verify golden-verify-protocol ## Verify all golden and protocol vectors.

# -----------------------------------------------------------------------------
# Static checks, fixes, and formatting
# -----------------------------------------------------------------------------

.PHONY: vet
vet: ## Run go vet.
	$(GO) vet $(PKGS)

.PHONY: fix
fix: go-fix ## Alias for go-fix.

.PHONY: go-fix
go-fix: ## Run go fix on all packages; modifies source when fixes apply.
	$(GO) fix $(PKGS)

.PHONY: go-fix-check
go-fix-check: ## Run go fix on all packages and print the patch as a unified diff
	$(GO) fix --diff $(PKGS)

.PHONY: lint
lint: ## Run golangci-lint.
	$(GOLANGCI_LINT) run

.PHONY: lint-fix
lint-fix: ## Run golangci-lint with automatic fixes.
	$(GOLANGCI_LINT) run --fix

.PHONY: fmt
fmt: fmt-go prettier ## Format Go files and Prettier-supported files.

.PHONY: fmt-check
fmt-check: fmt-go-check prettier-check ## Check Go and Prettier-supported formatting without modifying files.

.PHONY: fmt-go
fmt-go: ## Format all Go files with gofmt.
	@files=$$(find . -name '*.go' -not -path './.git/*' -print); \
	if [ -n "$$files" ]; then gofmt -w $$files; fi

.PHONY: fmt-go-check
fmt-go-check: ## Check Go formatting without modifying files.
	@files=$$(find . -name '*.go' -not -path './.git/*' -print); \
	if [ -n "$$files" ]; then \
		unformatted=$$(gofmt -l $$files); \
		if [ -n "$$unformatted" ]; then \
			echo "Go files need gofmt:"; \
			echo "$$unformatted"; \
			exit 1; \
		fi; \
	fi

.PHONY: prettier
prettier: ## Format Markdown, JSON, YAML, and other Prettier-supported files.
	@npx -y prettier -w . > /dev/null

.PHONY: prettier-check
prettier-check: ## Check Markdown, JSON, YAML, and other Prettier-supported files.
	@npx -y prettier -l .

.PHONY: tidy
tidy: ## Run go mod tidy.
	$(GO) mod tidy

.PHONY: tidy-check
tidy-check: ## Check go.mod and go.sum without modifying them.
	$(GO) mod tidy -diff

.PHONY: verify
verify: ## Verify module download checksums.
	$(GO) mod verify

.PHONY: check-wire-api
check-wire-api: ## Ensure production code uses only the object-level wire API.
	@violations=$$(find . -name '*.go' \
		-not -path './.git/*' \
		-not -path './internal/wire/*' \
		-not -path './internal/testutil/*' \
		-not -name '*_test.go' \
		-exec grep -ln 'wire\.MarshalFields\|wire\.UnmarshalFields\|RequireExactTags' {} \;); \
	if [ -n "$$violations" ]; then \
		echo "ERROR: field-level wire API found in production code:"; \
		echo "$$violations"; \
		echo "Use wire.Marshal/wire.Unmarshal instead."; \
		exit 1; \
	fi

.PHONY: check-transcript-api
check-transcript-api: ## Ensure custom SHA-256 transcripts use internal/transcript.
	@violations=$$(find . -name '*.go' \
		-not -path './.git/*' \
		-not -path './internal/transcript/*' \
		-not -name '*_test.go' \
		-exec grep -Eln 'sha256\.New[[:space:]]*\(' {} \;); \
	if [ -n "$$violations" ]; then \
		echo "ERROR: direct sha256.New() found outside internal/transcript:"; \
		echo "$$violations"; \
		echo "Use internal/transcript for custom SHA-256 transcripts."; \
		exit 1; \
	fi

# -----------------------------------------------------------------------------
# Combined workflows
# -----------------------------------------------------------------------------

.PHONY: fix-all
fix-all: go-fix lint-fix fmt tidy ## Apply source-modifying fixes, formatting, and module tidy.

.PHONY: check
check: build vet lint fmt-check tidy-check verify check-wire-api check-transcript-api go-fix-check ## Fast local pre-commit check.

.PHONY: ci
ci: check test-fast ## PR-grade checks; excludes source-modifying fixes, slowcrypto, race, stress, and long fuzzing.

.PHONY: nightly
nightly: ci test-integration test-slowcrypto test-race fuzz-ci ## Scheduled broad suite.

.PHONY: weekly
weekly: nightly test-stress fuzz-nightly ## Scheduled heavy suite.

.PHONY: clean
clean: ## Remove generated local reports.
	rm -f coverage.out coverage.html coverage.*.out coverage.*.html
