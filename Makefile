# Monorepo Makefile for the enforcer workspace.
# packages/enforcer ships a compiled binary; packages/pi is the standalone pi
# extension. Run `make help` for targets.

.PHONY: help bootstrap test fmt fmt-check lint typecheck check build install uninstall clean

.DEFAULT_GOAL := help

PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin
ENFORCER := packages/enforcer
PI := packages/pi

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

build: ## Compile the enforcer binary to dist/enforcer (bun single-file executable).
	mkdir -p dist
	cd $(ENFORCER) && bun x bun build src/cli.ts --compile --outfile ../../dist/enforcer

install: build ## Install the enforcer binary to $(BINDIR).
	install -d $(BINDIR) && install -m 0755 dist/enforcer $(BINDIR)/enforcer
	@echo "installed enforcer -> $(BINDIR)/enforcer"

uninstall: ## Remove the installed enforcer binary.
	rm -f $(BINDIR)/enforcer

clean: ## Remove installed deps, caches, and build output.
	rm -rf node_modules dist packages/*/node_modules
