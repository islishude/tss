# TSS - Go Threshold Signature Library
#
# Common targets for development and CI.
# Run `make help` for a summary.

.DEFAULT_GOAL := all

# ---- Build ----------------------------------------------------------------

.PHONY: build
build:
	go build ./...

# ---- Test -----------------------------------------------------------------

# Default: Tier 0 fast unit tests only (< 30s, no crypto keygen).
.PHONY: test
test:
	go test -short -timeout 1m ./...

# Tier 0 + Tier 1: Fast unit tests + small-param crypto correctness (< 2m).
.PHONY: test-fast
test-fast:
	go test -timeout 5m ./...

# Tier 2: Integration tests requiring full keygen/presign/sign (< 10m).
.PHONY: test-integration
test-integration:
	go test -tags=integration -timeout 20m ./...

# Tier 3: Production security-parameter smoke tests (1h).
.PHONY: test-slowcrypto
test-slowcrypto:
	go test -tags 'slowcrypto' -timeout 1h ./...

# Tier 4: Stress test with count=10 (>3h).
.PHONY: test-stress
test-stress:
	go test -race -tags 'stress slowcrypto integration' -count=10 -timeout 5h ./...

# Race detector over all packages (1h timeout).
.PHONY: test-race
test-race:
	go test -race -tags=integration -timeout 1h ./...

# Legacy test-coverage target (includes integration and slowcrypto tests).
.PHONY: test-coverage
test-coverage:
	go test -v -timeout 5h -tags 'integration slowcrypto' -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html

# Fuzzing testing
.PHONY: test-fuzzing
test-fuzzing:
	@./.github/scripts/fuzz-ci.sh

# CI: Fast build + vet + lint + format + tidy + Tier 0 + Tier 1.
.PHONY: ci
ci: build vet lint format tidy-check test-fast

# Nightly: CI + integration + slowcrypto + race + stress.
.PHONY: nightly
nightly: ci test-integration test-slowcrypto test-race test-stress

# ---- Lint -----------------------------------------------------------------

.PHONY: lint
lint:
	golangci-lint run

.PHONY: lint-fix
lint-fix:
	golangci-lint run --fix

# ---- Format ---------------------------------------------------------------

.PHONY: format
format:
	gofmt -w .
	npx -y prettier --write '*.md' 'docs'

.PHONY: format-check
format-check:
	gofmt -l .
	npx -y prettier --check '*.md' 'docs'

# ---- Maintenance ----------------------------------------------------------

.PHONY: fix
fix:
	go fix ./...

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: verify
verify:
	go mod verify

.PHONY: vet
vet:
	go vet ./...

# ---- Combined targets -----------------------------------------------------

.PHONY: check
check: build vet lint format-check tidy-check

.PHONY: tidy-check
tidy-check:
	go mod tidy -diff

.PHONY: all
all: build test-fast vet lint

# ---- Alias -----------------------------------------------------------------
.PHONY: test-count
test-count: test-stress

# ---- Help -----------------------------------------------------------------

.PHONY: help
help:
	@echo "TSS development targets:"
	@echo ""
	@echo "  build            compile all packages"
	@echo "  test             Tier 0 fast unit tests (< 30s)"
	@echo "  test-fast        Tier 0 + Tier 1: fast + small crypto (< 2m)"
	@echo "  test-integration Tier 2: keygen/presign/sign flows (< 10m)"
	@echo "  test-slowcrypto  Tier 3: production security params (< 45m)"
	@echo "  test-stress      Tier 4: stress with count=10 (3h)"
	@echo "  test-race        run tests with race detector (1h)"
	@echo "  test-coverage    run integration tests with coverage report"
	@echo "  ci               PR-ready: build + vet + lint + format + tidy + test-fast"
	@echo "  nightly          full suite: ci + integration + slowcrypto + race + stress"
	@echo "  lint             run golangci-lint"
	@echo "  lint-fix         run golangci-lint with auto-fix"
	@echo "  format           format go and markdown files with gofmt and prettier"
	@echo "  format-check     check go and markdown formatting (CI)"
	@echo "  fix              run go fix on all packages"
	@echo "  tidy             run go mod tidy"
	@echo "  verify           verify module integrity (go mod verify)"
	@echo "  vet              run go vet"
	@echo "  all              default: build + test-fast + vet + lint"
