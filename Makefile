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

.PHONY: test
test:
	go test -cover -timeout 25m ./...

.PHONY: test-race
test-race:
	go test -v -race -timeout 1h ./...

.PHONY: test-count
test-count:
	go test -v -count=10 -cover -timeout 3h ./...

.PHONY: test-coverage
test-coverage:
	go test -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html

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
all: build test vet lint

# ---- Help -----------------------------------------------------------------

.PHONY: help
help:
	@echo "TSS development targets:"
	@echo ""
	@echo "  build          compile all packages"
	@echo "  test           run tests (25m timeout)"
	@echo "  test-race      run tests with race detector (1h timeout)"
	@echo "  test-count     CI-grade stress tests (10 iterations, 1h timeout)"
	@echo "  test-coverage  run tests and produce coverage.{out,html}"
	@echo "  lint           run golangci-lint"
	@echo "  lint-fix       run golangci-lint with auto-fix"
	@echo "  format         format go and markdown files with gofmt and prettier"
	@echo "  format-check   check go and markdown formatting (CI)"
	@echo "  fix            run go fix on all packages"
	@echo "  tidy           run go mod tidy"
	@echo "  verify         verify module integrity (go mod verify)"
	@echo "  vet            run go vet"
	@echo "  check          CI-ready check: build + vet + lint + format + tidy"
	@echo "  all            default: build + test + vet + lint"
