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
  the existing Node helper).
- Build: **Rust stable** (1.77+) and **Node.js 20+**; Linux builders need
  WebKitGTK and GTK dev headers (see `.github/workflows/ci.yml`).
- Code signing is **not** configured; macOS users may need
  Right-click → Open and Windows users may see SmartScreen.

## Out of scope (for now)

- Bundling Node.js as a Tauri sidecar (planned).
- Native ClamAV / DNS / cron Tauri commands replacing the Express
  endpoints (planned, strangler pattern).
- Mobile (iOS / Android) targets.
- "Open at login" — temporarily removed during the Electron → Tauri
  migration; will return as a Tauri command.
