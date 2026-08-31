# ClamAV Control

## About this app

**ClamAV Control is not ClamAV.** It is a **control panel** (desktop app with a local web UI) for **configuring and controlling** ClamAV once it is installed on your computer. Think of it as a **companion utility**: it runs commands, edits config files, and surfaces status for you so setup and day-to-day configuration are easier than doing everything by hand in the terminal.

**ClamAV** is a free, open-source antivirus toolkit maintained under **[Cisco Talos / ClamAV](https://www.clamav.net/)**. It detects malware using regularly updated **signature databases**, and is widely used on servers and desktops (Linux, macOS, Windows). Typical components include **`freshclam`** (download signature updates), **`clamd`** (a background scanning daemon), and **`clamdscan`** / **`clamscan`** (run scans from the command line). You install that engine yourself (Homebrew, your Linux package manager, or the Windows installer from [clamav.net](https://www.clamav.net/)); **ClamAV Control** does not ship or embed the antivirus engine and only talks to the ClamAV tools already on your system. Licensing and trademarks for ClamAV itself are separate from this project (see the **License** section at the end of this file).

See **Features** below for the full list of what the panel can do (dashboard, scans, quarantine, config, schedules, DNS, settings, and more).

## How it is built

| Layer | Folder | Stack |
|-------|--------|-------|
| **Desktop shell + API** | `src-tauri/` | **Tauri 2** + Rust. Runs an in-process **axum** HTTP server that serves the UI and the natively ported `/api/*` routes, proxies the rest to the Node helper (strangler migration), and opens the WebView. |
| **Legacy helper** | `server/` | **Node.js / Express** — still handles the un-ported routes that talk to ClamAV (`freshclam`, `clamdscan`, etc.), DNS, cron. Bound to `127.0.0.1` only; being retired route-by-route. |
| **Web UI** | `client/` | **React + TypeScript (Vite)**. Production assets in `client/dist/`. |

At runtime the Tauri shell serves **axum on `127.0.0.1:38471`** (override with **`CLAMAV_GUI_PORT`**) and points the WebView at that URL. Axum answers the natively ported `/api/*` routes itself and forwards everything else to the Node helper on the internal port **`38470`** — so the existing same-origin React `fetch` and `EventSource` traffic keeps working unchanged while routes migrate to Rust.

The Tauri shell launches the Node helper on a **bundled Node.js runtime**, shipped with the app as a Tauri sidecar (`scripts/fetch-node-sidecar.mjs` + `bundle.externalBin`). System `node` on PATH is only a fallback for the rare case the sidecar is missing.

## Features

| Area | What it does |
|------|----------------|
| **Dashboard** | Definitions, scanner, daemon, firewall, real-time monitor, and DNS status; enable/disable real-time monitoring; definitions update; firewall and service actions where applicable. |
| **Real-time** | Full controls for folder monitoring (same engine as the Dashboard shortcut). |
| **Scan** | Standard / full / custom scans with streaming log, progress, and time estimates. |
| **Quarantine** | Review, restore, or delete quarantined files. |
| **Schedules** | Cron presets and raw crontab (macOS / Linux). |
| **Config** | Guided or raw editing of ClamAV config files. |
| **DNS** | Presets (e.g. OpenDNS, Google, Cloudflare), DHCP / automatic, or custom servers on supported platforms. |
| **Settings** | Refresh behavior, optional auto-start for real-time monitoring and the ClamAV daemon, optional default cron jobs on app open. |
| **Help** | In-app help and tab overview. |
| **Setup** | Guided ClamAV install via Homebrew on macOS; manual steps for other OSes. |

## Requirements

### Build

- **Rust stable (1.77+)** — [rustup](https://rustup.rs/).
- **Node.js 20+** with **`npm`**.
- **Linux only** (build host): WebKitGTK + GTK dev headers — see `.github/workflows/ci.yml`.

### Runtime (packaged app)

- **ClamAV** installed and on `PATH` (`freshclam`, `clamdscan`, etc.).
- Node.js is **bundled** with the app as a Tauri sidecar (staged by
  `scripts/fetch-node-sidecar.mjs`), so users do not need a system Node
  install. If the sidecar is missing the shell falls back to `node` on PATH.

## Build commands (canonical: `make`)

`make` is the standard top-level interface; it wraps the underlying `npm`, `cargo`, and Tauri CLIs so you don't have to remember each.

```bash
make help            # list all targets
make install         # one-time: install root + client + server deps
make dev             # run the Tauri desktop app in dev mode
make build           # build a release bundle for THIS OS
make check           # cargo check + client build (CI-style smoke)
make test            # Node script tests + all Rust tests (unit + integration)
make lint            # TypeScript build + `cargo clippy -D warnings`
make icons           # regenerate `build/`, `client/public/`, and `src-tauri/icons/`
make bump-version VERSION=1.1.0   # update version in all 5 places
make release VERSION=1.1.0        # bump + commit + tag + push (triggers CI)
make clean           # remove build artifacts
make clean-all       # also remove node_modules + cargo target
```

The npm scripts (`npm run tauri:dev`, `npm run tauri:build`, `npm run stage-tauri-bundle`, `npm run build:client`, `npm run prepare:server`, `npm run render-icon`, `npm run bump-version`) still exist as the underlying mechanism — `make` just calls them. Use whichever you prefer.

## Run from source (no installer)

```bash
git clone https://github.com/ronpicard/clamav-antivirus-control-gui.git
cd clamav-antivirus-control-gui
make install
make dev
```

`make dev` stages everything (server deps + client build + resource sync) and launches Tauri's dev runtime, which boots the Node helper on **`127.0.0.1:38471`** and opens a window pointed at it.

### UI development (hot reload)

Tauri's WebView talks to a same-origin Node helper, so for hot-reloaded React work it's still fastest to run client + server on their dev ports and use a normal browser:

```bash
# Terminal 1 — Node helper on port 3000
npm install --prefix server
cd server && npm run dev
```

```bash
# Terminal 2 — Vite on http://localhost:5173, /api → localhost:3000
npm install --prefix client
npm run dev --prefix client
```

Open **http://localhost:5173**. Re-run **`npm run tauri:dev`** when you want to verify the full desktop experience.

### Browser-only (optional)

```bash
npm run build:client
npm run prepare:server
cd server && npm start
```

Open **http://127.0.0.1:3000** (default port; set **`PORT`** if needed). The server serves the built UI from **`client/dist`**, or from **`CLIENT_DIST`** if that environment variable is set.

## Tests

```bash
make stage    # one-time per checkout: stage resources so the Tauri build script is satisfied
make test     # Node script tests + all Rust tests
```

`make test` runs two suites:

- **Node script tests** — `node --test "scripts/*.test.mjs"` (built-in Node test runner, no extra dependencies) covers the version-bump and resource-staging helpers, including a regression test for the v2.0.0 symlink-staging bug.
- **Rust tests** — `cargo test --locked` in `src-tauri/` runs the colocated unit tests (`#[cfg(test)]` modules next to each `features/` module: DNS presets, config, scan history, quarantine, error mapping, exec, paths) plus the integration test `src-tauri/tests/api_strangler.rs`, which boots the axum router and exercises every natively ported route.

The integration test's proxy fall-through assertions only run when **`CLAMAV_GUI_NODE_PORT`** points at a running Node helper (see the comment at the top of [api_strangler.rs](src-tauri/tests/api_strangler.rs)); without it those assertions are skipped, which keeps `cargo test` deterministic in CI. CI runs both suites on Linux, macOS, and Windows for every push and PR.

## Build installers

```bash
make install
make build
```

Outputs land under **`src-tauri/target/release/bundle/`**: `.dmg` / `.app` on macOS, `.msi` / NSIS `.exe` on Windows, `.AppImage` / `.deb` on Linux. On your machine, `make build` only produces installers for **that** OS.

### Continuous builds on GitHub

- **`.github/workflows/ci.yml`** runs cargo check, the Node script tests, all Rust tests, and a Tauri build on **Linux, macOS, and Windows** for every push and PR.
- **`.github/workflows/release.yml`** runs the same matrix on a tag push (e.g. **`v1.0.0`**) and uploads all three platforms to a **[GitHub Release](https://github.com/ronpicard/clamav-antivirus-control-gui/releases)** via `tauri-apps/tauri-action`.

**Unsigned builds:** On **macOS**, use **Right-click → Open** the first time. On **Windows**, SmartScreen may show "Windows protected your PC" for an unknown publisher — use **More info → Run anyway** if you trust the build. Code signing is not configured in this repo.

### App icon (developers)

Master artwork is **`assets/icon-source.png`**. The script writes the squircle-masked 1024×1024 PNG to **`assets/icon.png`** (used by Tauri's bundler) and to **`client/public/icon.png`** (served by Vite at `/icon.png` for the React header). Tauri's per-platform icon set lives under **`src-tauri/icons/`**.

```bash
make icons    # regenerates everything end-to-end
```

## Where files go

- **Scan folder:** `Documents/ClamAV-Scan` (created automatically; path is shown on the Dashboard).
- **Config paths:** Detected for typical Homebrew (Apple Silicon / Intel), Linux `/etc/clamav`, and Windows under Program Files when applicable.
- **Cron:** Supported on **Linux and macOS** only. On **Windows**, use Task Scheduler.

## Troubleshooting (packaged app)

If the window does not appear, check **`server.log`** in the app's user-data folder:

| OS | Typical path |
|----|----------------|
| **macOS** | `~/Library/Application Support/dev.clamav.gui/server.log` |
| **Windows** | `%APPDATA%\dev.clamav.gui\server.log` |
| **Linux** | `~/.config/dev.clamav.gui/server.log` |

If the folder name differs (older Electron builds used `clamav-antivirus-control-gui`), look under the same parent for any `clamav` / `dev.clamav.gui` directory.

## License

MIT — see [LICENSE](LICENSE).

ClamAV is a separate product; see [Cisco Talos / ClamAV](https://www.clamav.net/) for upstream licensing and trademarks.
