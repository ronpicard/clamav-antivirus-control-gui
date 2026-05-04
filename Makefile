# ClamAV Control — top-level Makefile
# `make` is the canonical entry point for build / release work.
# Commands are thin wrappers over npm + cargo + Tauri so the underlying
# tools stay debuggable.

# ---- Configuration ---------------------------------------------------------
SHELL          := /bin/bash
.SHELLFLAGS    := -eu -o pipefail -c
NPM            ?= npm
CARGO          ?= cargo
NODE           ?= node
TAURI_DIR      := src-tauri
CLIENT_DIR     := client
SERVER_DIR     := server
VERSION        ?=

# ---- Convenience -----------------------------------------------------------
.DEFAULT_GOAL  := help
.PHONY: help install install-root install-client install-server install-tauri \
        dev build build-debug check lint stage clean clean-all \
        icons render-icon tauri-icons \
        bump-version release pre-release-check \
        smoke

help: ## Show this help.
	@printf "ClamAV Control — make targets:\n\n"
	@awk 'BEGIN{FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@printf "\nExamples:\n  make install\n  make dev\n  make build\n  make release VERSION=1.1.0\n"

# ---- Install / setup -------------------------------------------------------
install: install-root install-client install-server ## Install all npm dependencies (root + client + server).

install-root: ## Install root npm deps (Tauri CLI, sharp).
	$(NPM) install

install-client: ## Install client npm deps.
	$(NPM) ci --prefix $(CLIENT_DIR)

install-server: ## Install server PRODUCTION npm deps (matches release bundle).
	$(NPM) ci --prefix $(SERVER_DIR) --omit=dev

install-tauri: ## Pull Rust crates into local cargo cache without compiling.
	cd $(TAURI_DIR) && $(CARGO) fetch

# ---- Stage Tauri inputs (server tree + built UI) ---------------------------
stage: ## Build client, install server prod deps, sync resources/.
	$(NPM) run build:client
	$(NPM) run prepare:server
	$(NPM) run sync-server-resources

# ---- Dev loop --------------------------------------------------------------
dev: ## Launch the Tauri shell in dev mode (stages inputs first).
	$(NPM) run tauri:dev

# ---- Production builds -----------------------------------------------------
build: ## Build a release bundle for the host OS.
	$(NPM) run tauri:build

build-debug: ## Build a debug bundle (faster, larger; for local smoke tests).
	cd $(TAURI_DIR) && $(CARGO) tauri build --debug || $(NPM) exec -- tauri build --debug

# ---- Verification ----------------------------------------------------------
check: ## cargo check (Tauri shell) + client production build.
	cd $(TAURI_DIR) && $(CARGO) check --locked
	$(NPM) run build:client

lint: ## TypeScript build + cargo clippy (warnings as errors).
	$(NPM) run build:client
	cd $(TAURI_DIR) && $(CARGO) clippy --locked --all-targets -- -D warnings

# ---- Icons -----------------------------------------------------------------
icons: render-icon tauri-icons ## Regenerate app icons end-to-end.

render-icon: ## Regenerate `assets/icon.png` and `client/public/icon.png`.
	$(NPM) run render-icon

tauri-icons: ## Regenerate `src-tauri/icons/*` from `assets/icon.png`.
	$(NPM) exec -- tauri icon ./assets/icon.png --output $(TAURI_DIR)/icons

# ---- Cleaning --------------------------------------------------------------
clean: ## Remove build artifacts (keeps node_modules and cargo cache).
	rm -rf $(CLIENT_DIR)/dist
	rm -rf $(TAURI_DIR)/resources $(TAURI_DIR)/gen $(TAURI_DIR)/target/release $(TAURI_DIR)/target/debug

clean-all: clean ## Also remove node_modules and cargo target.
	rm -rf node_modules $(CLIENT_DIR)/node_modules $(SERVER_DIR)/node_modules
	rm -rf $(TAURI_DIR)/target

# ---- Versioning + release flow --------------------------------------------
bump-version: ## Bump the version everywhere. Usage: `make bump-version VERSION=1.1.0`
ifeq ($(strip $(VERSION)),)
	@echo "error: VERSION is required (e.g. \`make bump-version VERSION=1.1.0\`)" >&2
	@exit 1
endif
	$(NODE) scripts/bump-version.mjs $(VERSION)

pre-release-check: check ## Sanity-checks before tagging (cargo check + client build + locked deps).
	@echo "Pre-release check passed."

release: pre-release-check ## Bump, commit, tag, and push. Usage: `make release VERSION=1.1.0`
ifeq ($(strip $(VERSION)),)
	@echo "error: VERSION is required (e.g. \`make release VERSION=1.1.0\`)" >&2
	@exit 1
endif
	$(NODE) scripts/bump-version.mjs $(VERSION)
	git add -A
	git commit -m "release: v$(VERSION)"
	git tag -a v$(VERSION) -m "ClamAV Control v$(VERSION)"
	git push origin HEAD
	git push origin v$(VERSION)
	@echo
	@echo "Tag v$(VERSION) pushed. CI is now building installers; watch:"
	@echo "  https://github.com/ronpicard/clamav-antivirus-control-gui/actions"

# ---- Smoke -----------------------------------------------------------------
smoke: stage ## Stage everything and run cargo check (fast \"does it still build\" gate).
	cd $(TAURI_DIR) && $(CARGO) check --locked
