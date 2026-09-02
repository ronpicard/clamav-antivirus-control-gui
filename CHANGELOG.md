# Changelog

All notable user-visible and release-worthy changes to **ClamAV Control** are
recorded here.

The format is based on [Keep a Changelog](https://keepachangelog.com/) and the
project follows semantic versioning.

## [Unreleased]

### Added
- **Unit test suites** alongside the existing integration test, all run by
  the new **`make test`** target and on every CI push:
  - Rust `#[cfg(test)]` modules colocated with each ported feature
    (`src-tauri/src/features/`): DNS presets, config GET, scan history,
    quarantine listing, API error mapping, exec wrapper, ClamAV path
    resolution.
  - Node built-in test runner (`node --test`) suites for the build scripts
    (`scripts/*.test.mjs`): version bumping and resource staging, including
    a **regression test** for the 2.0.0 symlink resource-staging fix.
- `tempfile` as a Rust dev-dependency (test-only temp directories).

### Changed
- **Status no longer reports "Attention needed" when the clamd daemon is
  off.** Manual scans and real-time protection run standalone `clamscan`,
  so a stopped daemon never reduced protection; only scheduled (cron) scans
  use `clamdscan`. The daemon now appears as its own **Scanner engine**
  row on Status with an on/off switch and a note about what it is for, and
  the sidebar badge stays green.
- **UI redesign** ported from the `clamav-antivirus-gui` repo: the top
  emoji tab bar is replaced by a grouped sidebar (Protection / System /
  Support) with `lucide-react` icons, a brand block with version badge, a
  live protection-status strip, and per-page headers (section eyebrow,
  title, description). The nav collapses to a horizontal scroller on
  narrow windows. Two tabs were renamed to match: **Instructions → Help**
  and **Auto-install → Setup**. New SVG favicon (`clamav-control.svg`).
  On large / fullscreen windows the sidebar pins to the window edge and
  the content column centers in the remaining space (no more dead
  gutters), with a subtle ambient gradient behind the content. The
  content column is now fluid — it widens up to 1560px (previously
  capped at 1030px) with viewport-scaled side padding, so panels
  expand on big windows and shrink cleanly down to the narrow-window
  breakpoint.
- CI now runs the full `cargo test --locked` (unit + integration) and the
  Node script tests on all three OSes, instead of only the axum
  integration test.

### Fixed
- **False "service on, daemon not answering yet" on macOS.** The health
  check's `pgrep -fl clamd` fallback substring-matched the `clamdscan
  --ping` probe the same health check runs concurrently, so the service
  was reported as running when no `clamd` process existed. The fallback
  now matches only an executable named exactly `clamd`.
- **"Try again" after a connection error** silently refreshed without
  showing the loading state (the click event object was passed as the
  `silent` flag). It now performs a normal, visible refresh. The client
  now also passes `tsc --noEmit` cleanly (two latent type errors fixed).
- **README architecture description** was stale: it said the Tauri shell
  starts the Node helper on port `38471`. Corrected to the strangler
  layout that shipped in 2.0.0 — axum serves `127.0.0.1:38471` and
  forwards un-ported routes to the Node helper on internal port `38470`.
  `RELEASE.md` § 7 updated to match (its steps 1–2 are done).

## [2.0.0] — 2026-05-04

> **Breaking architectural release.** The desktop shell migrated from
> **Electron** to **Tauri 2 + Rust** (different bundle format, different
> per-user app-data path, different installer artifacts). The "Open at
> login" Settings toggle is temporarily gone and will return as a native
> Tauri command in a follow-up release.

### Added — Express → Rust strangler migration (Phase 1)
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
- New Rust dependencies (each current-LTS / actively maintained):
  `axum 0.8`, `tower-http 0.6`, `reqwest 0.12`, `regex 1`, `which 7`,
  `anyhow 1`, `thiserror 2`, `once_cell 1`, `futures-util 0.3`,
  `http-body-util 0.1`, `bytes 1`, `dirs 5`.

### Changed — desktop shell (Electron → Tauri)
- Replaced the Electron shell with a **Tauri 2 + Rust** shell. Installer
  size drops from hundreds of MB (Chromium + Node bundled) to a small
  native binary that uses the OS WebView and the existing Node helper.
- CI now ships `.dmg` / `.app.tar.gz` (macOS), `.msi` / NSIS `.exe`
  (Windows), and `.AppImage` / `.deb` (Linux) via
  **`tauri-apps/tauri-action`**.
- Per-user app-data path moves with the new bundle ID **`dev.clamav.gui`**:
  - macOS: `~/Library/Application Support/dev.clamav.gui/`
  - Windows: `%APPDATA%\dev.clamav.gui\`
  - Linux: `~/.config/dev.clamav.gui/`

### Added — build & release tooling
- **Top-level `Makefile`** as the canonical command-line interface
  (`make help`). Wraps the npm + cargo + Tauri tooling so contributors
  don't have to remember each: `make install`, `make dev`, `make build`,
  `make check`, `make lint`, `make icons`, `make clean`,
  `make bump-version VERSION=…`, `make release VERSION=…`.
- **Version badge** in the top-left header showing the running app
  version (sourced from the root `package.json` and injected into the
  Vite bundle as `__APP_VERSION__`).
- **`scripts/bump-version.mjs`** + `make bump-version VERSION=<semver>`
  (or `npm run bump-version <semver>`) updates the version in **all
  five** places (`package.json`, `client/package.json`,
  `server/package.json`, `src-tauri/tauri.conf.json`,
  `src-tauri/Cargo.toml`) atomically.
- **`RELEASE.md`** — per-OS build prerequisites, local build commands,
  CI release flow, version-bump steps, smoke-test checklist,
  troubleshooting, and the runtime-Node migration plan.
- **`.github/workflows/ci.yml`** runs `cargo check --locked`, the new
  axum integration test, and a Tauri build smoke test on Linux / macOS /
  Windows for every push and PR.
- New `src-tauri/` Rust shell laid out feature-first under
  `src-tauri/src/features/`: paths, server lifecycle, UI/window, api.
- **`scripts/sync-server-resources.mjs`** stages the production Node
  server and built UI under `src-tauri/resources/` for the Tauri bundler.

### Fixed
- **Resource staging on hoisted `node_modules`.**
  `scripts/sync-server-resources.mjs` previously walked the tree with a
  hand-rolled `Dirent.isFile()` / `isDirectory()` filter, silently
  dropping symlinked packages (e.g. the `destroy` Express transitive
  dep) and breaking the Tauri bundler with
  `resource path 'resources/server/node_modules/destroy' doesn't exist`.
  Replaced with `fs.cpSync({ recursive: true, dereference: true })`,
  which follows symlinks. Verified on the Linux + Windows + macOS CI
  matrix.

### Removed
- The **`electron/`** shell (`main.cjs`, `preload.cjs`) and the
  `clamavGUI` preload bridge.
- The **"Open at login"** toggle in Settings — regressed during the
  Electron → Tauri swap; will return as a native Tauri command.
- The old `electron-release.yml` workflow (replaced by `release.yml`
  using `tauri-apps/tauri-action` and the new `ci.yml`).
- Untracked `release/` directory (electron-builder leftovers).
- Untracked empty `scan/` dev-scratch directory and root `.DS_Store`.
- `build/icon.png` was consolidated into `assets/icon.png` so the icon
  has a single source of truth under `assets/`.

### Notes
- **Packaged builds still need Node.js 20+ on PATH at runtime** — the
  Tauri shell launches the strangler axum server which forwards
  un-ported routes to the same Express helper as before. Phases 2–6 of
  the migration (`REQUIREMENTS.md` § Planned) progressively move every
  route into Rust and remove the Node spawn entirely.
