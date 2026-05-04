# Changelog

All notable user-visible and release-worthy changes to **ClamAV Control** are
recorded here.

The format is based on [Keep a Changelog](https://keepachangelog.com/) and the
project follows semantic versioning.

## [Unreleased]

### Added (Phase 1: Express → Rust strangler migration)
- **In-process axum HTTP server** in the Tauri Rust shell
  (`src-tauri/src/features/api/`). The webview now connects to axum on
  `127.0.0.1:38471`; axum serves the React static bundle and any natively
  ported `/api/*` route, and forwards everything else to the legacy Node
  helper (now bound to internal port `38470`).
- **Strangler proxy** (`features::api::proxy`) using `reqwest` + `axum`'s
  `OriginalUri` extractor so nested routes forward the un-stripped path.
  The proxy disappears once the last endpoint is native.
- **Native ports of the read-only "pure" endpoints** (no platform
  shell-outs, no shared in-memory state):
  - `GET /api/dns/presets`
  - `GET /api/scan/history`
  - `GET /api/quarantine`
  - `GET /api/config/:which` (clamd / freshclam)
- **Integration test** `src-tauri/tests/api_strangler.rs` exercises every
  ported route plus the proxy fall-through; runs on every CI push across
  Linux / macOS / Windows.
- New `dirs`, `axum`, `tower-http`, `reqwest`, `regex`, `which`,
  `anyhow`, `thiserror`, `once_cell`, `futures-util`, `http-body-util`,
  `bytes` Rust dependencies (each is current-LTS / actively maintained).

### Fixed
- **Resource staging on hoisted `node_modules`.** `scripts/sync-server-resources.mjs`
  copied entries with a hand-rolled walker that filtered on `Dirent.isFile()` /
  `isDirectory()`, silently dropping symlinked packages (e.g. the `destroy`
  Express transitive dep). The bundler then failed with
  `resource path 'resources/server/node_modules/destroy' doesn't exist`.
  Replaced with `fs.cpSync({ recursive: true, dereference: true })` which
  follows symlinks. Verified end-to-end on the Linux + Windows + macOS CI
  matrix.

### Removed (rules pass)
- Untracked **`release/`** directory (electron-builder leftovers from the
  pre-Tauri era).
- Untracked empty **`scan/`** dev scratch directory.
- Repo-root **`.DS_Store`** cruft.

### Changed (rules pass)
- Consolidated icon outputs: **`build/icon.png`** moved to
  **`assets/icon.png`** (single source of truth for app branding under
  `assets/`). Updated `scripts/render-app-icon.mjs`, `Makefile`,
  `README.md` references.
- Rewrote `native/macos-endpoint-security/README.md` Electron references
  to point at the Tauri shell.

### Added
- **Top-level `Makefile`** as the canonical command-line interface
  (`make help`). Wraps the existing npm + cargo + Tauri tooling so
  contributors don't have to remember each: `make install`, `make dev`,
  `make build`, `make check`, `make lint`, `make icons`, `make clean`,
  `make bump-version VERSION=…`, `make release VERSION=…`.
- **Version badge** in the top-left header showing the running app
  version (sourced from the root `package.json` and injected into the
  Vite bundle as `__APP_VERSION__`).
- **`scripts/bump-version.mjs`** + `make bump-version VERSION=<semver>`
  (or `npm run bump-version <semver>`) to update the version in
  **all five** places (`package.json`, `client/package.json`,
  `server/package.json`, `src-tauri/tauri.conf.json`,
  `src-tauri/Cargo.toml`) atomically.
- **`RELEASE.md`** — per-OS build prerequisites, local build commands,
  CI release flow, version-bump steps, smoke-test checklist,
  troubleshooting, and the runtime-Node migration plan.

### Changed
- Replaced the Electron shell with a **Tauri 2 + Rust** shell. Installer
  size drops from ~hundreds of MB (Chromium + Node bundled) to a small native
  binary that uses the OS WebView and the existing Node helper.
- CI now ships **`.dmg`**/**`.app.tar.gz`** (macOS), **`.msi`**/**`.exe`**
  (Windows), and **`.AppImage`**/**`.deb`** (Linux) via
  **`tauri-apps/tauri-action`**.

### Added
- New **`src-tauri/`** Rust shell (feature-first layout under
  `src-tauri/src/features/`): paths, server lifecycle, UI/window.
- **`scripts/sync-server-resources.mjs`** stages the production Node server
  and built UI under `src-tauri/resources/` for the Tauri bundler.
- New **`stage-tauri-bundle`** npm script chains
  `prepare:server → build:client → sync-server-resources` for one-step setup.
- **`.github/workflows/ci.yml`** runs cargo check + Tauri build smoke tests on
  Linux/macOS/Windows for every push/PR.

### Removed
- The **`electron/`** shell (`main.cjs`, `preload.cjs`) and the
  `clamavGUI` preload bridge are gone.
- The **Open at login** toggle in **Settings** is temporarily removed; it
  will return as a native Tauri command in a follow-up release.
- The old `electron-release.yml` workflow was replaced by `release.yml`
  (Tauri) and `ci.yml`.

### Notes
- Packaged builds still need **Node.js 20+** on PATH at runtime — the Tauri
  shell launches the same Express helper as before. Bundling Node as a
  Tauri sidecar binary is tracked for a future release.
