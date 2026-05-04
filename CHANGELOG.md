# Changelog

All notable user-visible and release-worthy changes to **ClamAV Control** are
recorded here.

The format is based on [Keep a Changelog](https://keepachangelog.com/) and the
project follows semantic versioning.

## [Unreleased]

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
