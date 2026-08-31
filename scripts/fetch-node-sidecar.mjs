/**
 * Downloads the official Node.js runtime and stages it under
 * `src-tauri/binaries/node-<target-triple>[.exe]` so Tauri bundles it as a
 * sidecar (`bundle.externalBin` in `tauri.conf.json`). End users then need
 * no system Node install; the shell prefers the bundled binary and only
 * falls back to PATH (see `src-tauri/src/features/server.rs`).
 *
 * Per host OS:
 *   macOS   — downloads darwin-arm64 + darwin-x64, `lipo`s them into a
 *             universal binary, and writes it under all three triples
 *             (aarch64 / x86_64 / universal-apple-darwin) so both plain
 *             and `--target universal-apple-darwin` builds find it.
 *   Linux   — host arch only (x86_64 / aarch64-unknown-linux-gnu).
 *   Windows — host arch only (x86_64 / aarch64-pc-windows-msvc), `.exe`.
 *
 * Archives are verified against the release's SHASUMS256.txt before
 * extraction. Downloads are skipped when the staged binaries already match
 * `NODE_VERSION` (stamp file `.node-sidecar-version`).
 */
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const NODE_VERSION = "22.12.0";
const DIST_BASE = `https://nodejs.org/dist/v${NODE_VERSION}`;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, "..");
const BIN_DIR = path.join(root, "src-tauri", "binaries");
const STAMP_FILE = path.join(BIN_DIR, ".node-sidecar-version");

/** Archives to fetch and sidecar files to produce for a given host. */
export function plan(platform = process.platform, arch = process.arch) {
  const dist = (suffix, ext) => ({
    file: `node-v${NODE_VERSION}-${suffix}.${ext}`,
    member: `node-v${NODE_VERSION}-${suffix}/${ext === "zip" ? "node.exe" : "bin/node"}`,
    key: suffix,
  });

  if (platform === "darwin") {
    return {
      downloads: [dist("darwin-arm64", "tar.gz"), dist("darwin-x64", "tar.gz")],
      universal: true,
      outputs: [
        "node-aarch64-apple-darwin",
        "node-x86_64-apple-darwin",
        "node-universal-apple-darwin",
      ],
    };
  }
  if (platform === "win32") {
    const a = arch === "arm64" ? "arm64" : "x64";
    const triple = arch === "arm64" ? "aarch64-pc-windows-msvc" : "x86_64-pc-windows-msvc";
    return {
      downloads: [dist(`win-${a}`, "zip")],
      universal: false,
      outputs: [`node-${triple}.exe`],
    };
  }
  const a = arch === "arm64" ? "arm64" : "x64";
  const triple = arch === "arm64" ? "aarch64-unknown-linux-gnu" : "x86_64-unknown-linux-gnu";
  return {
    downloads: [dist(`linux-${a}`, "tar.gz")],
    universal: false,
    outputs: [`node-${triple}`],
  };
}

export function isUpToDate(binDir = BIN_DIR, stampFile = STAMP_FILE, p = plan()) {
  try {
    if (fs.readFileSync(stampFile, "utf8").trim() !== NODE_VERSION) return false;
  } catch {
    return false;
  }
  return p.outputs.every((f) => fs.existsSync(path.join(binDir, f)));
}

export function sha256Of(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

/** Look up `file`'s checksum in SHASUMS256.txt content. */
export function expectedSha(shasumsText, file) {
  for (const line of shasumsText.split("\n")) {
    const m = line.trim().match(/^([0-9a-f]{64})\s+(.+)$/);
    if (m && m[2] === file) return m[1];
  }
  return null;
}

async function download(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`GET ${url}: HTTP ${r.status}`);
  return Buffer.from(await r.arrayBuffer());
}

function extractMember(archivePath, member, workDir) {
  // System tar handles .tar.gz everywhere; on Windows tar.exe is bsdtar,
  // which also extracts .zip.
  execFileSync("tar", ["-xf", archivePath, "-C", workDir, member], {
    stdio: ["ignore", "inherit", "inherit"],
  });
  return path.join(workDir, ...member.split("/"));
}

async function main() {
  const p = plan();
  if (isUpToDate()) {
    console.log(`fetch-node-sidecar: Node v${NODE_VERSION} already staged in ${path.relative(root, BIN_DIR)}`);
    return;
  }

  fs.mkdirSync(BIN_DIR, { recursive: true });
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "node-sidecar-"));
  try {
    console.log(`fetch-node-sidecar: fetching Node v${NODE_VERSION} checksums`);
    const shasums = (await download(`${DIST_BASE}/SHASUMS256.txt`)).toString("utf8");

    const extracted = {};
    for (const d of p.downloads) {
      console.log(`fetch-node-sidecar: downloading ${d.file}`);
      const buf = await download(`${DIST_BASE}/${d.file}`);
      const want = expectedSha(shasums, d.file);
      if (!want) throw new Error(`${d.file} not listed in SHASUMS256.txt`);
      const got = sha256Of(buf);
      if (got !== want) {
        throw new Error(`checksum mismatch for ${d.file}: expected ${want}, got ${got}`);
      }
      const archivePath = path.join(work, d.file);
      fs.writeFileSync(archivePath, buf);
      extracted[d.key] = extractMember(archivePath, d.member, work);
    }

    let source;
    if (p.universal) {
      source = path.join(work, "node-universal");
      execFileSync(
        "lipo",
        ["-create", ...Object.values(extracted), "-output", source],
        { stdio: ["ignore", "inherit", "inherit"] },
      );
    } else {
      source = Object.values(extracted)[0];
    }

    for (const out of p.outputs) {
      const dest = path.join(BIN_DIR, out);
      fs.copyFileSync(source, dest);
      if (process.platform !== "win32") fs.chmodSync(dest, 0o755);
    }
    fs.writeFileSync(STAMP_FILE, `${NODE_VERSION}\n`);
    console.log(
      `fetch-node-sidecar: staged ${p.outputs.join(", ")} → ${path.relative(root, BIN_DIR)}`,
    );
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}

// Run only when executed directly, so tests can import the helpers.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
