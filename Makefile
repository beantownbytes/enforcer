# Monorepo Makefile for the enforcer workspace.
# packages/enforcer ships a compiled binary; packages/pi is the standalone pi
# extension. Run `make help` for targets.

.PHONY: help bootstrap test fmt fmt-check lint typecheck check build build-linux-amd64 install uninstall clean version-check release-info

.DEFAULT_GOAL := help

PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin
ENFORCER := packages/enforcer
PI := packages/pi

# VERSION is the file the release pipeline owns; the binary reports the package
# manifest, because a compiled executable cannot go looking for a repo file. The
# release bump commit writes both, `make version-check` refuses a mismatch, and
# tests/cli.test.ts asserts they agree, so the released tag and the version the
# shipped binary prints cannot drift.
VERSION := $(shell tr -d '[:space:]' < VERSION 2>/dev/null || echo 0.0.0)
PKG_VERSION := $(shell grep -m1 '"version"' $(ENFORCER)/package.json | cut -d'"' -f4)
GIT_SHA := $(shell git rev-parse HEAD 2>/dev/null || echo unknown)

help: ## Print this help.
	@awk 'BEGIN {FS = ":.*##"; printf "Targets:\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

bootstrap: ## Install toolchain deps (bun packages), pinned to bun.lock. Idempotent.
	bun install --frozen-lockfile

typecheck: ## Type-check every workspace package.
	cd $(ENFORCER) && bun x tsc -p tsconfig.json --noEmit
	cd $(PI) && bun x tsc -p tsconfig.json --noEmit

fmt: ## Auto-format sources with biome.
	bun x @biomejs/biome check --write .

fmt-check: ## Verify biome formatting (non-zero on drift).
	bun x @biomejs/biome check .

lint: ## Biome lint across the workspace.
	bun x @biomejs/biome check .

test: ## Run the bun test suite.
	bun test

check: fmt-check typecheck lint test ## fmt-check + typecheck + lint + test. Pre-push gate.

build: version-check ## Compile the enforcer binary to dist/enforcer (bun single-file executable).
	mkdir -p dist
	cd $(ENFORCER) && bun x bun build src/cli.ts --compile --outfile ../../dist/enforcer

version-check: ## Fail when VERSION and the version compiled into the binary disagree.
	@test "$(VERSION)" = "$(PKG_VERSION)" || { \
		echo "version-check: VERSION says $(VERSION) but $(ENFORCER)/package.json says $(PKG_VERSION)" >&2; \
		exit 1; \
	}

build-linux-amd64: version-check ## Cross-compile the release binary to dist/enforcer-linux-amd64.
	mkdir -p dist
	cd $(ENFORCER) && bun x bun build src/cli.ts --compile --target=bun-linux-x64 --outfile ../../dist/enforcer-linux-amd64

release-info: ## Print "<bin> <version> <sha>" on one line for the release pipeline.
	@echo "enforcer $(VERSION) $(GIT_SHA)"

install: build ## Install the enforcer binary to $(BINDIR).
	install -d $(BINDIR) && install -m 0755 dist/enforcer $(BINDIR)/enforcer
	@echo "installed enforcer -> $(BINDIR)/enforcer"

uninstall: ## Remove the installed enforcer binary.
	rm -f $(BINDIR)/enforcer

clean: ## Remove installed deps, caches, and build output.
	rm -rf node_modules dist packages/*/node_modules
