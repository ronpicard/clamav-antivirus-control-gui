# Requirements

Source of truth for product, runtime, and build requirements of
**ClamAV Control**. Append in place; merge near-duplicates.

## Functional

- The desktop app MUST surface ClamAV daemon, definitions, scanner,
  firewall, real-time monitor, and DNS status in one Dashboard.
- The desktop app MUST run on macOS (10.15+), Windows 10+, and Linux
  (Debian/Ubuntu-class distros via `.deb` / `.AppImage`).
- The app MUST NOT replace ClamAV — it MUST only orchestrate the user's
  installed ClamAV tools and OS facilities.
- Real-time folder monitoring SHOULD be controllable from both the
  Dashboard shortcut and the Real-time tab.
- Scans SHOULD show live progress and an ETA.
- DNS controls SHOULD support presets (OpenDNS / Google / Cloudflare /
  family-safe variants) plus custom and DHCP.
- Schedules MUST use cron presets and a raw editor on macOS / Linux.
- Settings MUST allow optional auto-start of real-time monitoring,
  daemon, and default cron jobs on app open.

## Non-functional

- Installer download size SHOULD be substantially smaller than the
  Electron-era builds (Tauri 2 shell, OS WebView, no Chromium).
- The app MUST NOT bind to anything other than `127.0.0.1`.
- The app MUST NOT log secrets, credentials, or full payment data.

## Build / runtime

- Runtime: **Node.js 20+** must be installed on PATH (Tauri shell spawns
  the existing Node helper). This is **temporary** — see "Planned" below.
- Build: **Rust stable** (1.77+), **Node.js 20+**, and **GNU Make**.
  Linux builders need WebKitGTK and GTK dev headers (see
  `.github/workflows/ci.yml`).
- The canonical command-line interface is `make` (see `make help` or
  `RELEASE.md`). Direct npm / cargo invocations remain supported.
- Code signing is **not** configured; macOS users may need
  Right-click → Open and Windows users may see SmartScreen.

## Planned (in progress)

- **Drop the Node runtime requirement** — port the Express server
  (`server/index.js`) to an in-process **axum** HTTP server inside the
  Tauri shell, feature-by-feature (strangler pattern).
  - **Phase 1 — DONE.** Axum is live on the public port; `/api/dns/presets`,
    `/api/scan/history`, `/api/quarantine`, and `/api/config/:which` (GET)
    are native; everything else proxies to the Node helper on the
    internal port; integration test in `src-tauri/tests/api_strangler.rs`.
  - **Phase 2 — Writes & shell-outs**: `/api/config/:which` (PUT),
    `/api/config/reset`, `/api/actions/{firewall, restart-clamd,
    freshclam, clamd-service, realtime}`, `/api/dns/{status, apply}`.
  - **Phase 3 — SSE streams**: `/api/scan/stream`, `/api/scan/{start,
    cancel}`, `/api/actions/freshclam-stream`, `/api/realtime/stream`.
  - **Phase 4 — Install/uninstall flows**: `/api/install/{status, step,
    uninstall}` (multi-step + elevation).
  - **Phase 5 — Realtime watcher in Rust**: replace Node `fswatch` with
    the `notify` crate; port `/api/realtime/{status, start, stop, events}`.
  - **Phase 6 — Cutover**: delete `server/`, `prepare:server`, drop the
    `nodejs` `.deb` dependency, remove the proxy module and proxy port.
- **Bundle Node.js as a Tauri sidecar** as an interim if the full Rust
  port slips, so end users do not need to install Node manually.
- **"Open at login"** as a native Tauri command (regressed during the
  Electron → Tauri swap).
- **macOS Endpoint Security** ("block before open" preventative
  scanning) — see `native/macos-endpoint-security/` for the design notes
  and Swift sketch. Requires Apple's
  `com.apple.developer.endpoint-security.client` entitlement and a
  System Extension target.

## Conventions / known duplications

- The squircle-masked app icon is intentionally written to **two**
  locations by `scripts/render-app-icon.mjs`:
  - `assets/icon.png` — consumed by Tauri's bundler
    (`npx tauri icon ./assets/icon.png …`).
  - `client/public/icon.png` — Vite only ships static files from
    `public/`, so the React UI cannot symlink to `assets/`.
  Both are regenerated atomically by `make icons` from
  `assets/icon-source.png`.

## Cross-platform verification

- **CI on `main`** must build green on `macos-latest`, `ubuntu-latest`, and
  `windows-latest` (`.github/workflows/ci.yml`). This validates resource
  staging, `cargo check --locked`, and a real Tauri bundle on every OS.
- **macOS smoke** (manual): `make dev` → `/api/health`, DNS, firewall, daemon,
  real-time monitor endpoints all return `200` with populated payloads.
- **Windows / Linux smoke** beyond CI build is manual and gated on having
  ClamAV installed locally; CI only proves the shell + bundler works, not
  ClamAV control on those OSes.

## Out of scope

- Mobile (iOS / Android) targets.
