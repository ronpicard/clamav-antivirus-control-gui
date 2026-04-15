# ClamAV Control

Desktop app (Electron) with a local web UI to help configure **ClamAV** on your machine: status at a glance, update virus definitions, start or stop the scanning daemon, optional **real-time folder monitoring**, firewall toggles (where supported), **DNS resolver presets** on the active interface, edit `clamd.conf` / `freshclam.conf`, run scans with live progress and ETA, and manage cron jobs on Linux and macOS.

**This project does not replace ClamAV.** Install ClamAV separately (Homebrew, your Linux package manager, or the Windows installer). The UI talks to the tools already on your system.

## How it is built

- **`client/`** — React + TypeScript (Vite). Production assets go to `client/dist/`.
- **`server/`** — Express API and ClamAV integration (`node index.js`).
- **`electron/`** — Shell app: starts the server on **127.0.0.1** (port **38471** in packaged/dev Electron), loads the built UI, Dock/window icon, and **open at login** on desktop.
- Packaged apps ship **server** and **client/dist** under app resources; nothing listens on the public internet by default.

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
| **Settings** | Refresh behavior, optional auto-start for real-time monitoring and the ClamAV daemon, optional default cron jobs on app open, and **open at login** (Electron). |
| **Instructions** | In-app help and tab overview. |
| **Auto-install** | Guided ClamAV install via Homebrew on macOS; manual steps for other OSes. |

## Requirements

- **Node.js 20+** (to build or run from source)
- **ClamAV** installed and on your `PATH` (`freshclam`, `clamdscan`, etc.)

## npm scripts (repo root)

| Command | Purpose |
|---------|---------|
| `npm run electron` | Build the client, then launch Electron against the bundled stack. |
| `npm run dist` | Build client, install production server deps, run **electron-builder** → **`release/`**. |
| `npm run pack` | Same as `dist` but outputs an unpacked app dir (faster to sanity-check). |
| `npm run render-icon` | Regenerate **`build/icon.png`** and **`client/public/icon.png`** from **`assets/icon-source.png`**. |

## Run from source (no installer)

```bash
git clone https://github.com/ronpicard/clamav-antivirus-control-gui.git
cd clamav-antivirus-control-gui
npm install
npm run electron
```

This builds the React UI and opens the Electron window. The backend listens on **127.0.0.1:38471** only (override with **`CLAMAV_GUI_PORT`** if needed).

### UI development (hot reload)

Use two terminals so Vite can proxy API calls to the Node server:

```bash
# Terminal 1 — API on port 3000 (default)
npm install --prefix server
cd server && npm run dev
```

```bash
# Terminal 2 — Vite on http://localhost:5173, /api → localhost:3000
npm install --prefix client
npm run dev --prefix client
```

Open **http://localhost:5173**. For a full desktop run after UI changes, use **`npm run electron`** again.

### Browser-only (optional)

```bash
npm run build --prefix client
npm install --prefix server
cd server && npm start
```

Open **http://127.0.0.1:3000** (default port; set **`PORT`** if needed). The server serves the built UI from **`client/dist`** (repo root), or from **`CLIENT_DIST`** if that environment variable is set.

## Build installers

```bash
npm install
npm run dist
```

Outputs land in **`release/`** (e.g. `.dmg` / `.zip` on macOS, NSIS / portable on Windows, AppImage / `.deb` on Linux). CI can build per OS via **`.github/workflows/electron-release.yml`**.

Unsigned macOS builds may require **Right-click → Open** the first time. Code signing is not configured in this repo.

### App icon (developers)

Master artwork is **`assets/icon-source.png`**. **`build/icon.png`** and **`client/public/icon.png`** are generated as **1024×1024** PNGs with a **transparent squircle mask** (square output for the Dock and installers). After editing the source file, run:

```bash
npm run render-icon
```

Run **`npm run dist`** afterward so packaged builds pick up the new icon.

## Where files go

- **Scan folder:** `Documents/ClamAV-Scan` (created automatically; path is shown on the Dashboard).
- **Config paths:** Detected for typical Homebrew (Apple Silicon / Intel), Linux `/etc/clamav`, and Windows under Program Files when applicable.
- **Cron:** Supported on **Linux and macOS** only. On **Windows**, use Task Scheduler.

## Troubleshooting (macOS app)

If the window does not appear, check:

`~/Library/Application Support/clamav-antivirus-control-gui/server.log`

## License

MIT — see [LICENSE](LICENSE).

ClamAV is a separate product; see [Cisco Talos / ClamAV](https://www.clamav.net/) for upstream licensing and trademarks.
