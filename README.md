# ClamAV Control

Desktop app (Electron) with a local web UI to help configure **ClamAV** on your machine: check status, update virus definitions, edit `clamd.conf` / `freshclam.conf`, run scans inside a dedicated folder, and manage cron jobs on Linux and macOS.

**This project does not replace ClamAV.** Install ClamAV separately (Homebrew, your Linux package manager, or the Windows installer). The UI talks to the tools already on your system.

## Requirements

- **Node.js 20+** (to build or run from source)
- **ClamAV** installed and on your `PATH` (`freshclam`, `clamdscan`, etc.)

## Run from source (no installer)

```bash
git clone https://github.com/ronpicard/clamav-antivirus-control-gui.git
cd clamav-antivirus-control-gui
npm install
npm run electron
```

This builds the React UI and opens the Electron window. The backend listens on **127.0.0.1:38471** only.

### Browser-only (optional)

```bash
npm run build --prefix client
npm install --prefix server
cd server && npm start
```

Open **http://127.0.0.1:3000** (default port; set `PORT` if needed).

## Build installers

```bash
npm install
npm run dist
```

Outputs land in **`release/`** (e.g. `.dmg` / `.zip` on macOS, NSIS / portable on Windows, AppImage / `.deb` on Linux). CI can build per OS via `.github/workflows/electron-release.yml`.

Unsigned macOS builds may require **Right-click → Open** the first time. Code signing is not configured in this repo.

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
