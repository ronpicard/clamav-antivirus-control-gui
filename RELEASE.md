# Release guide

How to build **ClamAV Control** installers for **macOS, Windows, and Linux**, and how to bump the version everywhere it lives.

> The shipping app is a **Tauri 2** desktop shell + a **Node helper** + the **React UI**. CI is the source of truth for official releases; local builds are for testing.
>
> `make` is the canonical command-line interface — see `make help`. The npm scripts and direct cargo invocations still work and are documented as fallbacks.

---

## 1. One-time setup per OS

### All hosts

- **Rust stable (1.77+)** via [rustup](https://rustup.rs/).
- **Node.js 20+** with `npm`.
- **GNU Make** (preinstalled on macOS / Linux; on Windows use **Git Bash**, **WSL**, or `choco install make`).
- **Git**.

### macOS

```bash
xcode-select --install
rustup target add aarch64-apple-darwin x86_64-apple-darwin
```

The first command installs the Apple toolchain; the second adds both targets so `--target universal-apple-darwin` works.

### Windows

- Install **[Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)** (or full Visual Studio with the **Desktop development with C++** workload).
- **WebView2 Runtime** is preinstalled on Windows 10 1803+ / Windows 11. On older builds, install the [Evergreen Bootstrapper](https://developer.microsoft.com/microsoft-edge/webview2/).
- Install **GNU Make** (e.g. `choco install make`, or run from **Git Bash** which ships `make`).

### Linux (Debian / Ubuntu 22.04+)

```bash
sudo apt-get update
sudo apt-get install -y \
  libwebkit2gtk-4.1-dev \
  libgtk-3-dev \
  libayatana-appindicator3-dev \
  librsvg2-dev \
  patchelf \
  file \
  fakeroot \
  build-essential
```

> Older distros that only have **WebKitGTK 4.0** will not build a Tauri 2 app. Use Ubuntu 22.04+, Debian 12+, or Fedora 38+.

---

## 2. Local builds (smoke test)

From the repo root:

```bash
make install
make build
```

That stages the Node server + built UI into `src-tauri/resources/`, runs `cargo build --release`, and bundles for the **host OS** only.

| Host | Outputs (under `src-tauri/target/release/bundle/`) |
|------|----------------------------------------------------|
| **macOS** | `dmg/ClamAV Control_<ver>_<arch>.dmg`, `macos/ClamAV Control.app/` |
| **Windows** | `msi/ClamAV Control_<ver>_x64_en-US.msi`, `nsis/ClamAV Control_<ver>_x64-setup.exe` |
| **Linux** | `deb/clamav-control_<ver>_amd64.deb`, `appimage/clamav-control_<ver>_amd64.AppImage` |

To get a **macOS universal** binary locally:

```bash
cd src-tauri && cargo tauri build --target universal-apple-darwin
```

Useful supporting targets:

```bash
make check        # cargo check + client build (CI-style smoke)
make lint         # tsc + cargo clippy -D warnings
make clean        # remove build artifacts
make clean-all    # also remove node_modules + cargo target
```

---

## 3. Official releases via GitHub Actions

CI builds **macOS (universal), Windows, and Linux** in one matrix and uploads to a single **GitHub Release**.

### Trigger (one command)

```bash
make release VERSION=1.1.0
```

That runs the pre-release check (cargo check + client build), bumps the version everywhere, commits, tags `v1.1.0`, and pushes both `main` and the new tag — which fires `.github/workflows/release.yml`.

### Trigger (manual)

```bash
make bump-version VERSION=1.1.0
git add -A
git commit -m "release: v1.1.0"
git tag -a v1.1.0 -m "ClamAV Control v1.1.0"
git push origin main
git push origin v1.1.0
```

The **`Release`** workflow uses **`tauri-apps/tauri-action@v0`**. Watch it at:

```
https://github.com/ronpicard/clamav-antivirus-ui/actions
```

The published release lives at:

```
https://github.com/ronpicard/clamav-antivirus-ui/releases/tag/v<version>
```

### If CI fails with "Resource not accessible by integration"

GitHub can reject **release creation** from the workflow's `GITHUB_TOKEN`
even though the workflow requests `contents: write` (this bit the v2.1.0
release — every job built fine, then 403'd creating the release). The
workaround: create the release yourself, then re-run the failed jobs so
`tauri-action` finds the existing release and just uploads the installers
to it:

```bash
gh release create v<version> --title "ClamAV Control v<version>" --notes "..."
gh run rerun <run-id> --failed
```

### What CI builds

| OS | Bundles uploaded |
|----|------------------|
| **macOS (universal)** | `.dmg`, `.app.tar.gz` |
| **Windows** | `.msi`, NSIS `.exe` |
| **Linux** | `.deb`, `.AppImage` |

CI does **not** code-sign — see [§ 6](#6-code-signing).

### Pre-release smoke test (CI)

Every push and PR runs **`.github/workflows/ci.yml`**, which does `cargo check --locked`, the Node script tests (`npm run test:scripts`), all Rust tests (`cargo test --locked` — unit tests plus the axum integration test), and a Tauri build on **all three OSes** (no upload). If CI is red on `main`, do not tag.

---

## 4. Bumping the version

The same semver number lives in six places:

- `package.json` (root) — also drives the **UI version badge** via Vite's `define`.
- `client/package.json`
- `server/package.json`
- `src-tauri/tauri.conf.json` — Tauri bundle metadata.
- `src-tauri/Cargo.toml` — Rust crate version.
- `src-tauri/Cargo.lock` — the crate's own entry; CI builds with `--locked`
  and fails if this lags behind `Cargo.toml`.

```bash
make bump-version VERSION=1.1.0
```

It edits all six files in place, prints a diff hint, and tells you the next git steps. `make release VERSION=1.1.0` does bump + commit + tag + push for you.

Also update **`CHANGELOG.md`**: move bullets from `[Unreleased]` into a new `[1.1.0] — YYYY-MM-DD` section (Keep a Changelog format).

---

## 5. Pre-release checklist

Before tagging:

- [ ] `make build` passes locally.
- [ ] `make check` passes.
- [ ] `make test` passes.
- [ ] CI on `main` is green.
- [ ] `CHANGELOG.md` has a populated section for the new version.
- [ ] `make bump-version VERSION=<ver>` ran cleanly and the version badge in the running app shows the new value.
- [ ] If the icon changed: `make icons`, then rebuild.

After CI publishes:

- [ ] Download each platform's bundle, install/launch, and verify:
  - Version badge top-left shows the new version.
  - Dashboard reaches all-green (with ClamAV installed).
  - Real-time toggle works.
  - DNS panel renders without errors.

---

## 6. Code signing

Not configured in this repo. As a result:

- **macOS:** users will need **Right-click → Open** the first launch (Gatekeeper warning).
- **Windows:** **SmartScreen** may block first launch — **More info → Run anyway**.
- **Linux:** unsigned `.AppImage` / `.deb` install normally; users may want to verify the SHA from the GitHub Release page.

If signing is added later, the env vars to plumb into CI are typically:

| Env | Purpose |
|-----|---------|
| `APPLE_CERTIFICATE`, `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_ID`, `APPLE_PASSWORD`, `APPLE_TEAM_ID` | macOS sign + notarize |
| `WINDOWS_CERTIFICATE`, `WINDOWS_CERTIFICATE_PASSWORD` | Windows code signing (NSIS / MSI) |

`tauri-apps/tauri-action` auto-detects these.

---

## 7. Migration: dropping the runtime Node dependency

The packaged app currently still spawns a **Node helper** (the original Express server) on the internal port **`38470`**; the public port **`127.0.0.1:38471`** is served by the in-process **axum** server, which forwards un-ported routes to the helper. Removing the Node requirement is tracked work, not part of every release:

1. ~~Stand up a **Rust HTTP server** (**axum**) inside the Tauri shell.~~ Done (v2.0.0).
2. ~~Add a **reverse proxy** so the Rust server forwards unmigrated routes to the Node helper.~~ Done (v2.0.0).
3. Migrate endpoints feature-by-feature — strangler pattern. In progress: read-only DNS presets, scan history, quarantine list, and config GET are native; see `REQUIREMENTS.md` § Planned for the phase plan.
4. Once all endpoints are native, delete the Node spawn, server tree, and the `nodejs` `.deb` dependency.

Until that work lands, **`Node 20+` on PATH is a runtime requirement** for end users — see `REQUIREMENTS.md` and the README's **Requirements** section.

---

## 8. Troubleshooting

| Symptom | Fix |
|---------|-----|
| `glob pattern resources/server/**/* path not found` (cargo check or tauri build) | Run `make stage` first — it stages the Node server + `client/dist` into `src-tauri/resources/`. |
| `npm error path …/git/package.json` during `tauri dev` | Tauri's `beforeDevCommand` runs from the **repo root** (where `package.json` lives) — invoke `make dev` from the repo root. |
| Linux build fails with `No package 'webkit2gtk-4.1' found` | Install the dev headers from [§ 1 — Linux](#linux-debian--ubuntu-2204) or use Ubuntu 22.04+. |
| Windows build fails with `link.exe not found` | Install the **MSVC** workload (`cl.exe`/`link.exe`) from MS Build Tools. |
| macOS dev build fails with `xcrun: error: invalid active developer path` | `sudo xcode-select --install`. |
| App launches but window is blank | Check `~/Library/Application Support/dev.clamav.gui/server.log` (or `%APPDATA%\dev.clamav.gui\server.log` / `~/.config/dev.clamav.gui/server.log`). Most likely Node is not on PATH. |
| `make: command not found` on Windows | Open **Git Bash** or install Make: `choco install make`. |
