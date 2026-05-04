# ClamAV Control

## About this app

**ClamAV Control is not ClamAV.** It is a **control panel** (desktop app with a local web UI) for **configuring and controlling** ClamAV once it is installed on your computer. Think of it as a **companion utility**: it runs commands, edits config files, and surfaces status for you so setup and day-to-day configuration are easier than doing everything by hand in the terminal.

**ClamAV** is a free, open-source antivirus toolkit maintained under **[Cisco Talos / ClamAV](https://www.clamav.net/)**. It detects malware using regularly updated **signature databases**, and is widely used on servers and desktops (Linux, macOS, Windows). Typical components include **`freshclam`** (download signature updates), **`clamd`** (a background scanning daemon), and **`clamdscan`** / **`clamscan`** (run scans from the command line). You install that engine yourself (Homebrew, your Linux package manager, or the Windows installer from [clamav.net](https://www.clamav.net/)); **ClamAV Control** does not ship or embed the antivirus engine and only talks to the ClamAV tools already on your system. Licensing and trademarks for ClamAV itself are separate from this project (see the **License** section at the end of this file).

See **Features** below for the full list of what the panel can do (dashboard, scans, quarantine, config, schedules, DNS, settings, and more).

## How it is built

| Layer | Folder | Stack |
|-------|--------|-------|
| **Desktop shell** | `src-tauri/` | **Tauri 2** + Rust. Spawns the local helper, awaits health, opens the WebView. |
| **Local helper** | `server/` | **Node.js / Express** — talks to ClamAV (`freshclam`, `clamdscan`, etc.), DNS, cron. Bound to `127.0.0.1` only. |
| **Web UI** | `client/` | **React + TypeScript (Vite)**. Production assets in `client/dist/`. |

At runtime the Tauri shell starts the Node helper on **`127.0.0.1:38471`** (override with **`CLAMAV_GUI_PORT`**), waits for `/api/health`, and points the WebView at that URL — so the existing same-origin React `fetch` and `EventSource` traffic keeps working unchanged.

The Tauri shell launches **system Node.js**; **Node 20+ must be installed and on PATH** for the packaged app. Bundling Node as a Tauri sidecar is tracked in **`REQUIREMENTS.md`** as future work.

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
| **Instructions** | In-app help and tab overview. |
| **Auto-install** | Guided ClamAV install via Homebrew on macOS; manual steps for other OSes. |

## Requirements

### Build

- **Rust stable (1.77+)** — [rustup](https://rustup.rs/).
- **Node.js 20+** with **`npm`**.
- **Linux only** (build host): WebKitGTK + GTK dev headers — see `.github/workflows/ci.yml`.

### Runtime (packaged app)

- **Node.js 20+** on PATH (the Tauri shell launches the existing Node helper).
- **ClamAV** installed and on `PATH` (`freshclam`, `clamdscan`, etc.).

## npm scripts (repo root)

| Command | Purpose |
|---------|---------|
| `npm run tauri:dev` | Stage server + UI, then launch the desktop app in dev mode. |
| `npm run tauri:build` | Stage server + UI, then build installers for the host OS. |
| `npm run stage-tauri-bundle` | Run `prepare:server`, build the client, and copy both into `src-tauri/resources/`. |
| `npm run build:client` | Production build of the React UI. |
| `npm run prepare:server` | Install the server's production dependencies. |
| `npm run render-icon` | Regenerate `build/icon.png` and `client/public/icon.png` from `assets/icon-source.png`. Run `npx tauri icon ./build/icon.png --output src-tauri/icons` to refresh Tauri's icon set. |

## Run from source (no installer)

```bash
git clone https://github.com/ronpicard/clamav-antivirus-control-gui.git
cd clamav-antivirus-control-gui
npm install
npm run tauri:dev
```

The script stages everything (server deps + client build + resource sync) and launches Tauri's dev runtime, which boots the Node helper on **`127.0.0.1:38471`** and opens a window pointed at it.

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

## Build installers

```bash
npm install
npm run tauri:build
```

Outputs land under **`src-tauri/target/release/bundle/`**: `.dmg` / `.app` on macOS, `.msi` / NSIS `.exe` on Windows, `.AppImage` / `.deb` on Linux. On your machine, **`npm run tauri:build`** only produces installers for **that** OS.

### Continuous builds on GitHub

- **`.github/workflows/ci.yml`** runs cargo check + a Tauri build on **Linux, macOS, and Windows** for every push and PR (smoke test).
- **`.github/workflows/release.yml`** runs the same matrix on a tag push (e.g. **`v1.0.0`**) and uploads all three platforms to a **[GitHub Release](https://github.com/ronpicard/clamav-antivirus-control-gui/releases)** via `tauri-apps/tauri-action`.

**Unsigned builds:** On **macOS**, use **Right-click → Open** the first time. On **Windows**, SmartScreen may show "Windows protected your PC" for an unknown publisher — use **More info → Run anyway** if you trust the build. Code signing is not configured in this repo.

### App icon (developers)

Master artwork is **`assets/icon-source.png`**. **`build/icon.png`** and **`client/public/icon.png`** are generated as **1024×1024** PNGs with a transparent squircle mask. Tauri's bundle icons live in **`src-tauri/icons/`** (regenerate with **`npx tauri icon ./build/icon.png --output src-tauri/icons`** after editing the source).

```bash
npm run render-icon
npx tauri icon ./build/icon.png --output src-tauri/icons
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
