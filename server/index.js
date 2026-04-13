import express from "express";
import cors from "cors";
import crypto from "node:crypto";
import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import fs from "node:fs/promises";
import fsSync from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

function hostDefaultConfPaths() {
  const pl = process.platform;
  if (pl === "darwin") {
    const armDir = "/opt/homebrew/etc/clamav";
    const intelDir = "/usr/local/etc/clamav";
    if (fsSync.existsSync(path.join(armDir, "clamd.conf"))) {
      return { clamd: path.join(armDir, "clamd.conf"), freshclam: path.join(armDir, "freshclam.conf") };
    }
    if (fsSync.existsSync(path.join(intelDir, "clamd.conf"))) {
      return { clamd: path.join(intelDir, "clamd.conf"), freshclam: path.join(intelDir, "freshclam.conf") };
    }
    return { clamd: path.join(armDir, "clamd.conf"), freshclam: path.join(armDir, "freshclam.conf") };
  }
  if (pl === "win32") {
    const pf = process.env.ProgramFiles || "C:\\Program Files";
    return {
      clamd: path.join(pf, "ClamAV", "clamd.conf"),
      freshclam: path.join(pf, "ClamAV", "freshclam.conf"),
    };
  }
  return {
    clamd: "/etc/clamav/clamd.conf",
    freshclam: "/etc/clamav/freshclam.conf",
  };
}

const hostPaths = hostDefaultConfPaths();

function defaultScanRoot() {
  return path.join(os.homedir(), "Documents", "ClamAV-Scan");
}

const PORT = Number(process.env.PORT) || 3000;
const BIND_HOST = process.env.BIND_HOST || "127.0.0.1";
const CLAMD_CONF = process.env.CLAMD_CONF || hostPaths.clamd;
const FRESHCLAM_CONF = process.env.FRESHCLAM_CONF || hostPaths.freshclam;
const SCAN_ROOT = process.env.SCAN_ROOT || defaultScanRoot();
const CRON_USER = process.env.CRON_USER || os.userInfo().username;
const HISTORY_FILE = path.join(SCAN_ROOT, ".clamav-gui-scan-history.json");
const QUARANTINE_DIR = process.env.QUARANTINE_DIR || path.join(os.homedir(), "Documents", "ClamAV-Quarantine");
const SCAN_HISTORY_MAX = 80;
const scanSessions = new Map();
const defaultsDir = path.join(__dirname, "defaults");
let freshclamStreamBusy = false;
const ELEVATE_SERVICES = process.env.CLAMAV_GUI_NO_ELEVATE !== "1";

function crontabArgv(rest) {
  const isRoot = typeof process.getuid === "function" && process.getuid() === 0;
  if (isRoot) {
    return ["-u", CRON_USER, ...rest];
  }
  return [...rest];
}

function cronUnsupported(res) {
  return res.status(501).json({
    error: "Cron is not available on Windows. Use Task Scheduler or run the app on Linux/macOS.",
  });
}

const app = express();
app.use(cors({ origin: true }));
app.use(express.json({ limit: "2mb" }));

const clientDist =
  process.env.CLIENT_DIST || path.join(__dirname, "..", "client", "dist");

const SAFE_CWD = (() => {
  const home = os.homedir();
  if (home && fsSync.existsSync(home)) return home;
  if (fsSync.existsSync("/tmp")) return "/tmp";
  return "/";
})();

const EXTRA_PATH_DIRS = [
  "/opt/homebrew/bin",
  "/opt/homebrew/sbin",
  "/usr/local/bin",
  "/usr/local/sbin",
  "/usr/bin",
  "/usr/sbin",
  ...(process.platform === "win32"
    ? [
        path.join(process.env.ProgramFiles || "C:\\Program Files", "ClamAV"),
        path.join(process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)", "ClamAV"),
      ]
    : []),
];

(() => {
  const current = process.env.PATH || "";
  const sep = process.platform === "win32" ? ";" : ":";
  const parts = current.split(sep);
  const missing = EXTRA_PATH_DIRS.filter(
    (d) => !parts.includes(d) && fsSync.existsSync(d),
  );
  if (missing.length) {
    process.env.PATH = [...missing, ...parts].join(sep);
  }
})();

function resolveBinary(name) {
  const dirs = (process.env.PATH || "").split(process.platform === "win32" ? ";" : ":");
  const exts = process.platform === "win32" ? ["", ".exe", ".cmd", ".bat"] : [""];
  for (const dir of dirs) {
    for (const ext of exts) {
      const full = path.join(dir, name + ext);
      try {
        if (fsSync.existsSync(full) && fsSync.statSync(full).isFile()) return full;
      } catch { /* skip */ }
    }
  }
  return name;
}

const CLAMDSCAN_BIN = resolveBinary("clamdscan");
const CLAMSCAN_BIN = resolveBinary("clamscan");
const FRESHCLAM_BIN = resolveBinary("freshclam");

function runCmd(cmd, args, opts = {}) {
  const { env: envExtra, timeout, cwd, ...spawnOpts } = opts;
  return new Promise((resolve) => {
    let settled = false;
    const child = spawn(cmd, args, {
      ...spawnOpts,
      cwd: cwd || SAFE_CWD,
      env: { ...process.env, ...envExtra },
      timeout: timeout ?? undefined,
    });
    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (d) => {
      stdout += d.toString();
    });
    child.stderr?.on("data", (d) => {
      stderr += d.toString();
    });
    child.on("error", (e) => {
      if (!settled) {
        settled = true;
        resolve({ code: -1, stdout, stderr: stderr || String(e.message || e) });
      }
    });
    child.on("close", (code) => {
      if (!settled) {
        settled = true;
        resolve({ code, stdout, stderr });
      }
    });
  });
}

async function readFileSafe(p) {
  try {
    const data = await fs.readFile(p, "utf8");
    return { ok: true, content: data };
  } catch (e) {
    return { ok: false, error: String(e.message || e) };
  }
}

function parseClamdConfText(content) {
  const hints = { unixSocket: null, tcpHost: "127.0.0.1", tcpPort: null };
  if (!content) return hints;
  for (const line of content.split("\n")) {
    const t = line.replace(/#.*/, "").trim();
    if (!t) continue;
    let m = t.match(/^LocalSocket\s+(.+)$/i);
    if (m) hints.unixSocket = m[1].trim().replace(/^["']|["']$/g, "");
    m = t.match(/^TCPSocket\s+(\d+)/i);
    if (m) hints.tcpPort = Number(m[1]);
    m = t.match(/^TCPAddr\s+(\S+)/i);
    if (m) hints.tcpHost = m[1].trim();
  }
  return hints;
}

const DARWIN_CLAMD_SOCKET_CANDIDATES = [
  "/opt/homebrew/var/run/clamav/clamd.sock",
  "/opt/homebrew/var/run/clamav/clamd.ctl",
  "/usr/local/var/run/clamav/clamd.sock",
  "/usr/local/var/run/clamav/clamd.ctl",
  "/tmp/clamd.socket",
];

async function parseClamdConnectionFromDisk() {
  const hints = { unixSocket: null, tcpHost: "127.0.0.1", tcpPort: null };
  const r = await readFileSafe(CLAMD_CONF);
  if (r.ok) Object.assign(hints, parseClamdConfText(r.content));
  if (process.platform === "darwin") {
    if (!hints.unixSocket || !fsSync.existsSync(hints.unixSocket)) {
      for (const p of DARWIN_CLAMD_SOCKET_CANDIDATES) {
        if (fsSync.existsSync(p)) {
          hints.unixSocket = p;
          break;
        }
      }
    }
  }
  return hints;
}

/** Ping clamd via clamdscan --ping. Try with --config-file first, then bare --fdpass. */
async function tryClamdPing() {
  const attempts = [];

  if (fsSync.existsSync(CLAMD_CONF)) {
    attempts.push({
      args: ["--config-file", CLAMD_CONF, "--ping", "1"],
      label: `config:${CLAMD_CONF}`,
    });
  }
  attempts.push({ args: ["--ping", "1"], label: "default --ping" });
  const probeFile = process.platform === "win32"
    ? "NUL"
    : fsSync.existsSync("/usr/bin/true")
      ? "/usr/bin/true"
      : fsSync.existsSync("/bin/true")
        ? "/bin/true"
        : "/dev/null";
  attempts.push({ args: ["--fdpass", probeFile], label: "fdpass probe" });

  let last = "";
  for (const { args, label } of attempts) {
    const r = await runCmd(CLAMDSCAN_BIN, args, { timeout: 20_000 });
    const out = (r.stdout || "") + (r.stderr || "");
    if (r.code === 0 || /PONG|OK|Empty file/i.test(out)) {
      return { ok: true, method: label, detail: out.trim().slice(0, 300) };
    }
    last = out.trim().slice(0, 500) || `exit ${r.code}`;
  }
  return { ok: false, method: null, detail: last || "clamdscan could not reach clamd" };
}

/** Build clamdscan args for one-shot scanning (non-streaming). */
async function buildClamdscanScanArgs(targetPath) {
  if (fsSync.existsSync(CLAMD_CONF)) {
    return ["--config-file", CLAMD_CONF, "--fdpass", "-v", targetPath];
  }
  return ["--fdpass", "-v", targetPath];
}

/** Build clamscan args for streaming per-file output in live scan sessions. */
function buildClamscanArgs(targets) {
  const paths = Array.isArray(targets) ? targets : [targets];
  const args = ["-r", "-v", "--stdout"];
  if (fsSync.existsSync(CLAMD_CONF)) {
    const r = readFileSafeSync(CLAMD_CONF);
    if (r) {
      const dbMatch = r.match(/^\s*DatabaseDirectory\s+(.+)$/im);
      if (dbMatch) {
        const dbDir = dbMatch[1].trim();
        if (fsSync.existsSync(dbDir)) args.push("--database", dbDir);
      }
    }
  }
  try { fsSync.mkdirSync(QUARANTINE_DIR, { recursive: true }); } catch { /* ignore */ }
  args.push(`--move=${QUARANTINE_DIR}`);
  args.push(...paths);
  return args;
}

function readFileSafeSync(p) {
  try {
    return fsSync.readFileSync(p, "utf8");
  } catch {
    return null;
  }
}

async function writeFileSafe(p, content) {
  const dir = path.dirname(p);
  await fs.mkdir(dir, { recursive: true });
  const backup = `${p}.bak.${Date.now()}`;
  try {
    await fs.copyFile(p, backup);
  } catch {
    /* first write */
  }
  await fs.writeFile(p, content, "utf8");
  return { backup };
}

function brewExecutableSync() {
  const candidates = ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"];
  for (const p of candidates) {
    try {
      if (fsSync.existsSync(p) && fsSync.statSync(p).isFile()) return p;
    } catch {
      /* ignore */
    }
  }
  return null;
}

async function resolveBrewPath() {
  const direct = brewExecutableSync();
  if (direct) return direct;
  try {
    const { stdout } = await execFileAsync("which", ["brew"], { encoding: "utf8", cwd: SAFE_CWD });
    const p = stdout.trim().split("\n")[0];
    if (p && fsSync.existsSync(p)) return p;
  } catch {
    /* ignore */
  }
  return null;
}

async function homebrewPrefixFromBrew(brewPath) {
  if (!brewPath) return null;
  try {
    const { stdout } = await execFileAsync(brewPath, ["--prefix"], { encoding: "utf8", cwd: SAFE_CWD });
    const p = stdout.trim().split(/\n/)[0];
    return p || null;
  } catch {
    return null;
  }
}

function clamdConfDefinesListener(content) {
  for (const line of content.split(/\n/)) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    if (/^(LocalSocket|TCPSocket)\s/i.test(t)) return true;
  }
  return false;
}

function insertHomebrewClamdBlock(content, prefix) {
  const block = `\n# ClamAV Control — Homebrew listener (added automatically)\nDatabaseDirectory ${prefix}/var/lib/clamav\nLocalSocket ${prefix}/var/run/clamav/clamd.sock\nFixStaleSocket yes\n`;
  const needle = "# Example";
  const idx = content.indexOf(needle);
  if (idx >= 0) {
    const lineEnd = content.indexOf("\n", idx);
    if (lineEnd === -1) return content + block;
    return content.slice(0, lineEnd + 1) + block + content.slice(lineEnd + 1);
  }
  return block + content;
}

async function ensureHomebrewClamdLayout(brewPath, clamdConfPath) {
  const prefix =
    (await homebrewPrefixFromBrew(brewPath)) ||
    brewExecutableSync()?.replace(/\/bin\/brew$/, "") ||
    "/opt/homebrew";
  const runDir = path.join(prefix, "var", "run", "clamav");
  await fs.mkdir(runDir, { recursive: true });

  let content;
  let existed = false;
  try {
    content = await fs.readFile(clamdConfPath, "utf8");
    existed = true;
  } catch {
    const sample = path.join(path.dirname(clamdConfPath), "clamd.conf.sample");
    try {
      content = await fs.readFile(sample, "utf8");
      existed = false;
    } catch {
      content = `##
## Minimal clamd.conf for Homebrew (created by ClamAV Control)
##
# Example
`;
      existed = false;
    }
  }

  content = content
    .split("\n")
    .map((line) => (line.trim() === "Example" ? "# Example" : line))
    .join("\n");

  let changed = false;
  if (!clamdConfDefinesListener(content)) {
    content = insertHomebrewClamdBlock(content, prefix);
    changed = true;
  }

  if (!existed || changed) {
    await writeFileSafe(clamdConfPath, content);
  }

  let freshclamWrote = false;
  const freshclamConf = FRESHCLAM_CONF;
  try {
    await fs.access(freshclamConf);
  } catch {
    const dbDir = path.join(prefix, "var", "lib", "clamav");
    await fs.mkdir(dbDir, { recursive: true });
    const sample = path.join(path.dirname(freshclamConf), "freshclam.conf.sample");
    let fc;
    try {
      fc = await fs.readFile(sample, "utf8");
    } catch {
      fc = `##\n## freshclam.conf (created by ClamAV Control)\n##\n# Example\n`;
    }
    fc = fc.split("\n").map((line) => (line.trim() === "Example" ? "# Example" : line)).join("\n");
    if (!/^\s*DatabaseDirectory\s/m.test(fc)) {
      fc += `\n# ClamAV Control — Homebrew database path (added automatically)\nDatabaseDirectory ${dbDir}\n`;
    }
    if (!/^\s*DatabaseMirror\s/m.test(fc)) {
      fc += `DatabaseMirror database.clamav.net\n`;
    }
    await writeFileSafe(freshclamConf, fc);
    freshclamWrote = true;
  }

  return { prefix, runDir, clamdConfPath, wrote: !existed || changed, freshclamWrote, listenerConfigured: clamdConfDefinesListener(content) };
}

async function gatherInstallStatus() {
  const pl = process.platform;
  const brewPath = pl === "darwin" ? await resolveBrewPath() : null;
  let brewVersion = null;
  let clamavFromBrew = false;
  if (brewPath) {
    const v = await runCmd(brewPath, ["--version"]);
    if (v.code === 0) brewVersion = (v.stdout || "").split("\n")[0].trim() || "ok";
    const listed = await runCmd(brewPath, ["list", "clamav"]);
    clamavFromBrew = listed.code === 0;
  }

  const prefix = pl === "darwin" ? await homebrewPrefixFromBrew(brewPath) : null;
  let confExists = false;
  let listenerConfigured = false;
  try {
    const raw = await fs.readFile(CLAMD_CONF, "utf8");
    confExists = true;
    listenerConfigured = clamdConfDefinesListener(raw);
  } catch {
    confExists = false;
  }

  const clamdscan = await runCmd(CLAMDSCAN_BIN, ["--version"]).catch((e) => ({
    code: 1,
    stdout: "",
    stderr: String(e),
  }));
  const freshclam = await runCmd(FRESHCLAM_BIN, ["--version"]).catch((e) => ({
    code: 1,
    stdout: "",
    stderr: String(e),
  }));

  const canAutomate = pl === "darwin" && !!brewPath;
  const manualSteps = [];
  if (pl === "darwin" && !brewPath) {
    manualSteps.push({
      title: "Install Homebrew (if needed)",
      command: '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"',
    });
  }
  if (pl === "darwin" && brewPath) {
    manualSteps.push({ title: "Install ClamAV", command: `${brewPath} install clamav` });
    manualSteps.push({
      title: "Start daemon",
      command: `${brewPath} services start clamav`,
    });
  }
  if (pl === "linux") {
    manualSteps.push({
      title: "Debian / Ubuntu",
      command: "sudo apt update && sudo apt install -y clamav clamav-daemon clamav-freshclam",
    });
    manualSteps.push({
      title: "Fedora",
      command: "sudo dnf install -y clamav clamav-update clamd",
    });
  }
  if (pl === "win32") {
    manualSteps.push({
      title: "Windows installer",
      command: "Download ClamAV for Windows from https://www.clamav.net/downloads",
    });
  }

  return {
    platform: pl,
    canAutomate,
    brew: {
      path: brewPath,
      version: brewVersion,
      clamavInstalled: clamavFromBrew,
    },
    paths: {
      homebrewPrefix: prefix,
      clamdConf: CLAMD_CONF,
      confExists,
      listenerConfigured,
    },
    binaries: {
      clamdscanOk: clamdscan.code === 0 || String(clamdscan.stdout + clamdscan.stderr).includes("ClamAV"),
      freshclamOk: !(freshclam.stderr || "").includes("ENOENT") || freshclam.code === 0 || String(freshclam.stdout + freshclam.stderr).includes("ClamAV"),
    },
    manualSteps,
    uninstall: buildUninstallHints(pl, brewPath, clamavFromBrew),
  };
}

function buildUninstallHints(pl, brewPath, clamavFromBrew) {
  const manualSteps = [];
  if (pl === "darwin" && brewPath) {
    manualSteps.push({
      title: "Stop service and remove formula",
      command: `${brewPath} services stop clamav 2>/dev/null; ${brewPath} services stop clamd 2>/dev/null; ${brewPath} uninstall --force clamav; ${brewPath} autoremove`,
    });
  }
  if (pl === "linux") {
    manualSteps.push({
      title: "Debian / Ubuntu (terminal)",
      command: "sudo apt-get remove --purge -y clamav clamav-daemon clamav-freshclam",
    });
    manualSteps.push({
      title: "Fedora",
      command: "sudo dnf remove -y clamav clamav-update clamd",
    });
  }
  if (pl === "win32") {
    manualSteps.push({
      title: "Windows",
      command: "Settings → Apps → ClamAV → Uninstall (or run the ClamAV uninstaller from Program Files)",
    });
  }
  const canAutomated =
    (pl === "darwin" && !!brewPath && clamavFromBrew) || (pl === "linux" && ELEVATE_SERVICES);
  return { canAutomated, manualSteps };
}

async function uninstallHomebrewClamav(brewPath) {
  const phases = [];
  const push = (name, r, extra = {}) => {
    phases.push({
      name,
      ok: r.code === 0,
      code: r.code,
      stderr: String(r.stderr || "").slice(0, 4000),
      stdout: String(r.stdout || "").slice(0, 2000),
      terminalLogs: Array.isArray(r.terminalLogs) ? r.terminalLogs : undefined,
      ...extra,
    });
  };

  const brewRun = (args, timeout) => runBrewDarwinFirstThenElevate(brewPath, args, { timeout });

  for (const svc of ["clamav", "clamd"]) {
    const r = await brewRun(["services", "stop", svc], 120_000);
    push(`brew services stop ${svc}`, r, { brewUsedAdminRetry: !!r.brewUsedAdminRetry });
  }

  const u = await brewRun(["uninstall", "--force", "clamav"], 600_000);
  push("brew uninstall --force clamav", u, { brewUsedAdminRetry: !!u.brewUsedAdminRetry });

  const a = await brewRun(["autoremove"], 180_000);
  push("brew autoremove", a, { brewUsedAdminRetry: !!a.brewUsedAdminRetry });

  const plist = path.join(os.homedir(), "Library", "LaunchAgents", "homebrew.mxcl.clamav.plist");
  try {
    await fs.unlink(plist);
    phases.push({ name: "removed ~/Library/LaunchAgents/homebrew.mxcl.clamav.plist", ok: true });
  } catch (e) {
    phases.push({
      name: "removed user LaunchAgents plist",
      ok: false,
      detail: String(e.message || e),
    });
  }

  const prefix = await homebrewPrefixFromBrew(brewPath);
  if (prefix) {
    const sock = path.join(prefix, "var", "run", "clamav", "clamd.sock");
    try {
      await fs.unlink(sock);
      phases.push({ name: "removed clamd socket (as user)", ok: true });
    } catch {
      const adm = await runDarwinAdminBash(`rm -f ${bashSingleQuote(sock)}`);
      phases.push({
        name: "removed clamd socket (admin rm only — no brew)",
        ok: adm.ok,
        detail: combineExecOutput(adm).slice(0, 2000),
        stdout: adm.stdout,
        stderr: adm.stderr,
        terminalLogs: [
          logFromExecService(
            "osascript admin shell: rm -f clamd.sock",
            "/usr/bin/osascript",
            ["-e", "(administrator password)"],
            adm,
            { via: "rm only, no brew" },
          ),
        ],
      });
    }
  }

  return {
    ok: u.code === 0,
    phases,
    brewPolicy: "user_first_then_one_admin_retry_if_permission_error",
  };
}

async function uninstallLinuxClamav() {
  const phases = [];
  const pk = await resolvePkexec();

  const tryApt = async (usePk) => {
    const cmd = usePk && pk ? pk : "apt-get";
    const args =
      usePk && pk
        ? ["apt-get", "remove", "-y", "--purge", "clamav", "clamav-daemon", "clamav-freshclam"]
        : ["remove", "-y", "--purge", "clamav", "clamav-daemon", "clamav-freshclam"];
    return execService(cmd, args);
  };

  const tryDnf = async (usePk) => {
    const cmd = usePk && pk ? pk : "dnf";
    const args =
      usePk && pk
        ? ["dnf", "remove", "-y", "clamav", "clamav-update", "clamd"]
        : ["remove", "-y", "clamav", "clamav-update", "clamd"];
    return execService(cmd, args);
  };

  let r = await tryApt(false);
  phases.push({
    name: "apt-get remove/purge (user)",
    ok: r.ok,
    stdout: r.stdout,
    stderr: r.stderr,
    detail: combineExecOutput(r).slice(0, 4000),
  });
  if (r.ok) return { ok: true, phases, elevated: false };

  if (ELEVATE_SERVICES && pk && isLikelyPermissionFailure(combineExecOutput(r))) {
    await new Promise((t) => setTimeout(t, BREW_RETRY_AFTER_PERMISSION_MS));
    r = await tryApt(true);
    phases.push({
      name: "pkexec apt-get remove/purge (after permission failure)",
      ok: r.ok,
      stdout: r.stdout,
      stderr: r.stderr,
      detail: combineExecOutput(r).slice(0, 4000),
    });
    if (r.ok) return { ok: true, phases, elevated: true };
  }

  r = await tryDnf(false);
  phases.push({
    name: "dnf remove (user)",
    ok: r.ok,
    stdout: r.stdout,
    stderr: r.stderr,
    detail: combineExecOutput(r).slice(0, 4000),
  });
  if (r.ok) return { ok: true, phases, elevated: false };

  if (ELEVATE_SERVICES && pk && isLikelyPermissionFailure(combineExecOutput(r))) {
    await new Promise((t) => setTimeout(t, BREW_RETRY_AFTER_PERMISSION_MS));
    r = await tryDnf(true);
    phases.push({
      name: "pkexec dnf remove (after permission failure)",
      ok: r.ok,
      stdout: r.stdout,
      stderr: r.stderr,
      detail: combineExecOutput(r).slice(0, 4000),
    });
    if (r.ok) return { ok: true, phases, elevated: true };
  }

  if (!ELEVATE_SERVICES) {
    return {
      ok: false,
      phases,
      message:
        "Uninstall as user failed. Enable elevation (unset CLAMAV_GUI_NO_ELEVATE) for pkexec, or run sudo apt/dnf in a terminal.",
    };
  }
  if (!pk) {
    return {
      ok: false,
      phases,
      message: "pkexec not found. Run sudo apt remove … or sudo dnf remove … in a terminal.",
    };
  }

  return {
    ok: false,
    phases,
    elevated: false,
    message: "Neither apt nor dnf uninstall succeeded. Remove ClamAV packages manually.",
  };
}

function resolveScanTarget(userPath) {
  const normalized = path.normalize(userPath || "").replace(/^(\.\.(\/|\\|$))+/, "");
  const full = path.resolve(SCAN_ROOT, normalized);
  const root = path.resolve(SCAN_ROOT);
  if (!full.startsWith(root + path.sep) && full !== root) {
    return null;
  }
  return full;
}

function fullSystemScanRoot() {
  if (process.platform === "win32") {
    const drive = process.env.SystemDrive || "C:";
    return path.normalize(`${drive}\\`);
  }
  return "/";
}

/** Absolute paths must stay under home or the app scan folder. Relative paths use SCAN_ROOT jail. */
function resolveCustomScanTarget(userPath) {
  const p = String(userPath ?? ".").trim();
  if (!p) return null;
  if (path.isAbsolute(p)) {
    const resolved = path.resolve(p);
    const home = path.resolve(os.homedir());
    const scan = path.resolve(SCAN_ROOT);
    const underHome = resolved === home || resolved.startsWith(home + path.sep);
    const underScan = resolved === scan || resolved.startsWith(scan + path.sep);
    if (underHome || underScan) return resolved;
    return null;
  }
  return resolveScanTarget(p);
}

function standardScanDirs() {
  const home = os.homedir();
  const candidates = [
    path.join(home, "Downloads"),
    path.join(home, "Documents"),
    path.join(home, "Desktop"),
    path.join(home, "Applications"),
    SCAN_ROOT,
  ];
  if (process.platform === "win32") {
    const userProfile = process.env.USERPROFILE || home;
    candidates.push(path.join(userProfile, "AppData", "Local", "Temp"));
  } else {
    candidates.push("/tmp");
  }
  const existing = [];
  for (const d of candidates) {
    try {
      if (fsSync.existsSync(d) && fsSync.statSync(d).isDirectory()) {
        if (!existing.includes(d)) existing.push(d);
      }
    } catch { /* skip */ }
  }
  return existing.length > 0 ? existing : [home];
}

function resolveScanRequest(body) {
  const mode = body?.mode || "custom";
  if (mode === "quick") {
    const dirs = standardScanDirs();
    return { target: dirs.join("\n"), targets: dirs, mode: "quick" };
  }
  if (mode === "full") {
    const t = fullSystemScanRoot();
    return { target: t, targets: [t], mode: "full" };
  }
  const target = resolveCustomScanTarget(body?.path);
  return target ? { target, targets: [target], mode: "custom" } : { target: null, targets: [], mode: "custom" };
}

function scanTargetLabel(mode, target) {
  if (mode === "quick") return "Standard scan (Downloads, Documents, Desktop, …)";
  if (mode === "full") return "Full system";
  const rel = path.relative(path.resolve(SCAN_ROOT), target);
  if (rel && !rel.startsWith("..")) return rel || ".";
  return target;
}

async function execQuick(cmd, args) {
  try {
    const { stdout, stderr } = await execFileAsync(cmd, args, {
      maxBuffer: 512 * 1024,
      timeout: 8000,
      cwd: SAFE_CWD,
    });
    return { ok: true, stdout: String(stdout || ""), stderr: String(stderr || "") };
  } catch (e) {
    return { ok: false, stdout: String(e.stdout || ""), stderr: String(e.stderr || e.message || e) };
  }
}

const SERVICE_CMD_TIMEOUT_MS = 120_000;

function resolveHomebrewBin() {
  const candidates = ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"];
  for (const p of candidates) {
    if (fsSync.existsSync(p)) return p;
  }
  return "brew";
}

function combineExecOutput(r) {
  const a = String(r.stdout || "").trim();
  const b = String(r.stderr || "").trim();
  if (a && b) return `${b}\n${a}`;
  return b || a || "";
}

const TERMINAL_LOG_MAX_CHARS = 56_000;

function truncateTerminalText(s) {
  const t = String(s ?? "");
  if (t.length <= TERMINAL_LOG_MAX_CHARS) return t;
  return `${t.slice(0, TERMINAL_LOG_MAX_CHARS)}\n… [truncated, total ${t.length} characters]`;
}

function terminalLogEntry({ label, argv, stdout, stderr, code, extra }) {
  const c = typeof code === "number" ? code : 1;
  return {
    label: label || "",
    argv: Array.isArray(argv) ? argv : argv ? [String(argv)] : [],
    stdout: truncateTerminalText(stdout),
    stderr: truncateTerminalText(stderr),
    code: c,
    ok: c === 0,
    ...(extra && typeof extra === "object" ? extra : {}),
  };
}

function logFromRunCmd(label, cmd, args, r, extra) {
  return terminalLogEntry({
    label,
    argv: [cmd, ...(Array.isArray(args) ? args : [])],
    stdout: r.stdout,
    stderr: r.stderr,
    code: r.code,
    extra,
  });
}

function logFromExecService(label, cmd, args, r, extra) {
  return terminalLogEntry({
    label,
    argv: [cmd, ...(Array.isArray(args) ? args : [])],
    stdout: r.stdout,
    stderr: r.stderr,
    code: r.ok ? 0 : 1,
    extra,
  });
}

function terminalLogsFromUninstallPhases(phases) {
  const out = [];
  for (const p of phases || []) {
    if (Array.isArray(p.terminalLogs) && p.terminalLogs.length) {
      out.push(...p.terminalLogs);
      continue;
    }
    out.push(
      terminalLogEntry({
        label: p.name,
        argv: [],
        stdout: p.stdout != null ? String(p.stdout) : "",
        stderr: [p.stderr, p.detail].filter(Boolean).join("\n").trim(),
        code: typeof p.code === "number" ? p.code : p.ok ? 0 : 1,
      }),
    );
  }
  return out;
}

async function execService(cmd, args, opts = {}) {
  const timeoutMs = typeof opts.timeout === "number" ? opts.timeout : SERVICE_CMD_TIMEOUT_MS;
  try {
    const { stdout, stderr } = await execFileAsync(cmd, args, {
      maxBuffer: 4 * 1024 * 1024,
      timeout: timeoutMs,
      cwd: SAFE_CWD,
    });
    return { ok: true, stdout: String(stdout || ""), stderr: String(stderr || "") };
  } catch (e) {
    return {
      ok: false,
      stdout: String(e.stdout || ""),
      stderr: String(e.stderr || e.message || e),
    };
  }
}

/**
 * macOS: show native admin password dialog, then run bash script body.
 *
 * `osascript do shell script … with administrator privileges` runs /bin/sh as root, inheriting
 * the *parent's* cwd.  If that directory is deleted or TCC-protected, the shell-init getcwd()
 * call fails before any script code runs ("error retrieving current directory").
 *
 * Workaround: write the script to a temp file (world-readable) and tell osascript to execute
 * `/bin/bash /tmp/<file>` so that bash's own getcwd in shell-init doesn't matter (the file path
 * is absolute).  We also prepend `cd /tmp` in the script so brew/freshclam see a traversable cwd.
 */
async function runDarwinAdminBash(scriptBody, execOpts = {}) {
  const userHome = os.homedir();
  const homeQ = bashSingleQuote(userHome);
  const fullScript = `#!/bin/bash
cd /tmp 2>/dev/null || cd / 2>/dev/null || true
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:\$PATH"
export HOME=${homeQ}
export TMPDIR="/private/tmp"
cd ${homeQ} 2>/dev/null || cd /private/tmp 2>/dev/null || cd /tmp 2>/dev/null || cd / 2>/dev/null || true
${scriptBody}
`;
  const tmpFile = path.join("/tmp", `.clamav-gui-admin-${process.pid}-${Date.now()}.sh`);
  await fs.writeFile(tmpFile, fullScript, { mode: 0o755 });
  try {
    const shellCmd = `/bin/bash ${bashSingleQuote(tmpFile)}`;
    const appleScript = `do shell script ${JSON.stringify(shellCmd)} with administrator privileges`;
    return await execService("/usr/bin/osascript", ["-e", appleScript], execOpts);
  } finally {
    fs.unlink(tmpFile).catch(() => {});
  }
}

async function resolvePkexec() {
  if (!ELEVATE_SERVICES) return null;
  if (fsSync.existsSync("/usr/bin/pkexec")) return "/usr/bin/pkexec";
  const w = await execQuick("which", ["pkexec"]);
  const line = (w.stdout || "").trim().split("\n")[0];
  return line || null;
}

/** Windows: run `cmd /c <line>` with UAC; returns child exit code via PowerShell. */
async function runWindowsElevatedCmdC(line, execOpts = {}) {
  const ps = `$p = Start-Process -FilePath cmd.exe -ArgumentList '/c',${JSON.stringify(line)} -Verb RunAs -PassThru -Wait; if ($null -eq $p -or $null -eq $p.ExitCode) { exit 1 } else { exit $p.ExitCode }`;
  return execService("powershell.exe", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps], execOpts);
}

function bashSingleQuote(s) {
  return `'${String(s).replace(/'/g, `'\\''`)}'`;
}

/** Detect errors where retrying with elevation / pkexec / launchctl is appropriate. */
function isLikelyPermissionFailure(text) {
  const t = String(text || "").toLowerCase();
  return /permission denied|operation not permitted|\beacces\b|\beperm\b|not authorized|interactive authentication required|access denied|must be root|must be run as root|only root|authentication is required|failed to connect to bus|not allowed|could not be started|bootstrap failed|working directory must be readable|may not chdir|can't open|cannot open|couldn't create|could not create|unable to (open|create|write)|denied writing|read-only file system|readonly file system/i.test(
    t,
  );
}

/** Detect brew service errors that need a launchctl-based admin retry (not just permission issues). */
function isBrewServiceNeedsElevation(text) {
  const t = String(text || "");
  if (isLikelyPermissionFailure(t)) return true;
  if (/is started as.*root/i.test(t)) return true;
  if (/Formula.*is not installed/i.test(t)) return true;
  return false;
}

const FRESHCLAM_TIMEOUT_MS = 600_000;
const BREW_RETRY_AFTER_PERMISSION_MS = 650;

/**
 * Run freshclam once with elevation (admin dialog / pkexec / UAC). Used after a user-level run fails with
 * permission-style errors — same policy as brew/service actions (never start elevated by default).
 */
async function runElevatedFreshclamOnly() {
  const pl = process.platform;
  if (pl === "darwin") {
    const scriptBody = `
set +e
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
'${FRESHCLAM_BIN.replace(/'/g, "'\\''")}'
code=$?
exit $code
`;
    const r = await runDarwinAdminBash(scriptBody, { timeout: FRESHCLAM_TIMEOUT_MS });
    return {
      ok: r.ok,
      stdout: r.stdout,
      stderr: r.stderr,
      via: "osascript: do shell script … with administrator privileges",
    };
  }
  if (pl === "linux") {
    const pk = await resolvePkexec();
    if (!pk) {
      return {
        ok: false,
        stdout: "",
        stderr: "pkexec not found. Run sudo freshclam in a terminal.",
        via: null,
      };
    }
    const r = await runCmd(pk, [FRESHCLAM_BIN], { timeout: FRESHCLAM_TIMEOUT_MS });
    return {
      ok: r.code === 0,
      stdout: r.stdout,
      stderr: r.stderr,
      via: "pkexec freshclam",
    };
  }
  if (pl === "win32") {
    const r = await runWindowsElevatedCmdC(FRESHCLAM_BIN, { timeout: FRESHCLAM_TIMEOUT_MS });
    return {
      ok: r.ok,
      stdout: r.stdout,
      stderr: r.stderr,
      via: "UAC: elevated cmd /c freshclam",
    };
  }
  return { ok: false, stdout: "", stderr: "Elevation not supported on this platform.", via: null };
}

/**
 * User freshclam first; on permission-style failure optionally retry once elevated (macOS / Linux / Windows).
 * @param {(line: string) => void} [onRetryNotice] — e.g. SSE line when retrying
 */
async function runFreshclamWithOptionalElevation(onRetryNotice) {
  const terminalLogs = [];
  const first = await runCmd(FRESHCLAM_BIN, [], { timeout: FRESHCLAM_TIMEOUT_MS });
  terminalLogs.push(logFromRunCmd("freshclam (your user)", FRESHCLAM_BIN, [], first));

  if (first.code === 0) {
    return {
      ok: true,
      code: 0,
      stdout: first.stdout,
      stderr: first.stderr,
      usedElevation: false,
      terminalLogs,
    };
  }

  const blob = `${first.stdout}\n${first.stderr}`;
  if (!ELEVATE_SERVICES || !isLikelyPermissionFailure(blob)) {
    return {
      ok: false,
      code: first.code,
      stdout: first.stdout,
      stderr: first.stderr,
      usedElevation: false,
      terminalLogs,
    };
  }

  await new Promise((r) => setTimeout(r, BREW_RETRY_AFTER_PERMISSION_MS));
  onRetryNotice?.(
    "Permission error detected; retrying freshclam with elevated privileges (you may be prompted for a password).",
  );

  const second = await runElevatedFreshclamOnly();
  const extra = second.via ? { via: second.via } : {};
  terminalLogs.push(
    terminalLogEntry({
      label: "freshclam (elevated retry)",
      argv: ["freshclam"],
      stdout: second.stdout,
      stderr: second.stderr,
      code: second.ok ? 0 : 1,
      extra,
    }),
  );

  return {
    ok: second.ok,
    code: second.ok ? 0 : 1,
    stdout: [first.stdout, second.stdout].filter(Boolean).join("\n"),
    stderr: [first.stderr, second.stderr].filter(Boolean).join("\n").trim(),
    usedElevation: true,
    terminalLogs,
  };
}

/**
 * Locate a Homebrew-generated plist for ClamAV.
 * brew services generates these in predictable locations.
 */
function findBrewClamavPlist(prefix) {
  const candidates = [
    path.join(prefix || "/opt/homebrew", "opt", "clamav", "homebrew.mxcl.clamav.plist"),
    path.join(os.homedir(), "Library", "LaunchAgents", "homebrew.mxcl.clamav.plist"),
    "/Library/LaunchDaemons/homebrew.mxcl.clamav.plist",
  ];
  for (const p of candidates) {
    if (fsSync.existsSync(p)) return p;
  }
  return null;
}

/**
 * macOS: after user `brew services start` fails for ClamAV (it almost always does because
 * clamd needs root), we use launchctl via the admin password dialog to load the service as a
 * system LaunchDaemon.  This is NOT `sudo brew` — it only touches launchctl.
 * If there is no plist at all, fall back to running brew services start once through the
 * admin shell (some Homebrew versions only generate it on start).
 */
async function darwinElevatedServiceStart(brewPath, svcName) {
  const prefix = await homebrewPrefixFromBrew(brewPath) ||
    brewPath?.replace(/\/bin\/brew$/, "") || "/opt/homebrew";
  const srcPlist = findBrewClamavPlist(prefix);
  const destPlist = "/Library/LaunchDaemons/homebrew.mxcl.clamav.plist";

  if (srcPlist) {
    const scriptBody = `
set +e
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
DEST=${bashSingleQuote(destPlist)}
SRC=${bashSingleQuote(srcPlist)}
if [ "$SRC" != "$DEST" ]; then
  cp "$SRC" "$DEST" 2>/dev/null
fi
chown root:wheel "$DEST" 2>/dev/null
chmod 644 "$DEST" 2>/dev/null
/bin/launchctl bootout system "$DEST" 2>/dev/null
/bin/launchctl bootstrap system "$DEST"
code=$?
if [ $code -ne 0 ]; then
  /bin/launchctl load -w "$DEST" 2>/dev/null
  code=$?
fi
echo "clamav-gui: Loaded ClamAV system LaunchDaemon via administrator password dialog." >&2
exit $code
`;
    return runDarwinAdminBash(scriptBody);
  }

  const scriptBody = `
set +e
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
BREW=${bashSingleQuote(brewPath)}
"$BREW" services start ${bashSingleQuote(svcName)}
code=$?
echo "clamav-gui: Ran brew services start as root (no user-plist found to load directly)." >&2
exit $code
`;
  return runDarwinAdminBash(scriptBody);
}

/**
 * macOS: stop a ClamAV LaunchDaemon via admin shell (launchctl bootout / unload)
 * and remove the root-owned plist + user LaunchAgents plist so brew's service
 * registry returns to a clean state where user-level `brew services start` can work.
 */
async function darwinElevatedServiceStop() {
  const destPlist = "/Library/LaunchDaemons/homebrew.mxcl.clamav.plist";
  const userPlist = path.join(os.homedir(), "Library", "LaunchAgents", "homebrew.mxcl.clamav.plist");
  const scriptBody = `
set +e
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
/bin/launchctl bootout system ${bashSingleQuote(destPlist)} 2>/dev/null
/bin/launchctl unload -w ${bashSingleQuote(destPlist)} 2>/dev/null
rm -f ${bashSingleQuote(destPlist)} 2>/dev/null
rm -f ${bashSingleQuote(userPlist)} 2>/dev/null
/usr/bin/killall clamd 2>/dev/null
echo "clamav-gui: Stopped ClamAV system LaunchDaemon and cleaned up root-owned plists." >&2
exit 0
`;
  return runDarwinAdminBash(scriptBody);
}

/**
 * macOS: never start with sudo brew. Run `brew <args>` as the current user first.
 * For brew service start/stop commands, if the user attempt fails with a permission-like error
 * we use launchctl (NOT sudo brew) via the admin dialog to load/unload the daemon plist.
 * For non-service brew commands (install, uninstall, etc.) the admin retry re-runs brew
 * through the admin shell (equivalent to sudo for that one command).
 */
async function runBrewDarwinFirstThenElevate(brewPath, args, opts = {}) {
  const terminalLogs = [];
  const first = await runCmd(brewPath, args, opts);
  terminalLogs.push(logFromRunCmd("brew (login user)", brewPath, args, first));
  if (first.code === 0) {
    return { ...first, brewUsedAdminRetry: false, terminalLogs };
  }
  const blob = `${first.stdout}\n${first.stderr}`;
  const isServiceCmd = args[0] === "services";
  const isServiceStart = isServiceCmd && (args[1] === "start" || args[1] === "restart");
  const isServiceStop = isServiceCmd && args[1] === "stop";
  const shouldRetry = isServiceCmd
    ? isBrewServiceNeedsElevation(blob)
    : isLikelyPermissionFailure(blob);
  if (process.platform !== "darwin" || !shouldRetry) {
    return { ...first, brewUsedAdminRetry: false, terminalLogs };
  }

  await new Promise((r) => setTimeout(r, BREW_RETRY_AFTER_PERMISSION_MS));

  let second;
  let retryLabel;
  if (isServiceStart) {
    second = await darwinElevatedServiceStart(brewPath, args[2] || "clamav");
    retryLabel = "launchctl load (admin password — system LaunchDaemon)";
  } else if (isServiceStop) {
    second = await darwinElevatedServiceStop();
    retryLabel = "launchctl unload (admin password — system LaunchDaemon)";
  } else {
    const argsQ = args.map(bashSingleQuote).join(" ");
    const scriptBody = `
set +e
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
BREW=${bashSingleQuote(brewPath)}
"$BREW" ${argsQ}
code=$?
echo "clamav-gui: Retried this brew command after a permission error using the administrator password dialog." >&2
exit $code
`;
    second = await runDarwinAdminBash(scriptBody);
    retryLabel = "brew (administrator password retry)";
  }

  terminalLogs.push(
    terminalLogEntry({
      label: retryLabel,
      argv: isServiceStart || isServiceStop
        ? ["launchctl", isServiceStart ? "bootstrap" : "bootout", "system", "homebrew.mxcl.clamav.plist"]
        : [brewPath, ...args],
      stdout: second.stdout,
      stderr: second.stderr,
      code: second.ok ? 0 : 1,
      extra: { via: "osascript: do shell script … with administrator privileges" },
    }),
  );
  const mergedStderr = [first.stderr, second.stderr, second.ok ? "" : combineExecOutput(second)]
    .filter(Boolean)
    .join("\n");
  return {
    code: second.ok ? 0 : 1,
    stdout: [first.stdout, second.stdout].filter(Boolean).join("\n"),
    stderr: mergedStderr.trim(),
    brewUsedAdminRetry: true,
    terminalLogs,
  };
}

async function getFirewallStatus() {
  const pl = process.platform;
  if (pl === "darwin") {
    const fw = await execQuick("/usr/libexec/ApplicationFirewall/socketfilterfw", [
      "--getglobalstate",
    ]);
    if (fw.ok && /Firewall is enabled/i.test(fw.stdout)) {
      return { active: true, source: "macOS Application Firewall", detail: fw.stdout.trim() };
    }
    if (fw.ok && /Firewall is disabled/i.test(fw.stdout)) {
      return { active: false, source: "macOS Application Firewall", detail: fw.stdout.trim() };
    }
    const def = await execQuick("defaults", ["read", "/Library/Preferences/com.apple.alf", "globalstate"]);
    if (def.ok) {
      const n = parseInt(String(def.stdout).trim(), 10);
      if (!Number.isNaN(n)) {
        return {
          active: n >= 1,
          source: "macOS (alf globalstate)",
          detail: `globalstate=${n} (1+=on)`,
        };
      }
    }
    return { active: null, source: "unknown", detail: "Could not read firewall state" };
  }
  if (pl === "linux") {
    const ufw = await execQuick("ufw", ["status"]);
    if (ufw.ok) {
      const on = /Status:\s*active/i.test(ufw.stdout);
      return { active: on, source: "ufw", detail: ufw.stdout.split("\n")[0] || ufw.stdout.trim() };
    }
    const fw = await execQuick("firewall-cmd", ["--state"]);
    if (fw.ok) {
      const on = fw.stdout.trim() === "running";
      return { active: on, source: "firewalld", detail: fw.stdout.trim() };
    }
    return { active: null, source: "unknown", detail: "ufw / firewalld not detected" };
  }
  if (pl === "win32") {
    const ns = await execQuick("netsh", ["advfirewall", "show", "allprofiles", "state"]);
    if (ns.ok) {
      const on = /\bON\b/i.test(ns.stdout);
      return { active: on, source: "Windows Defender Firewall", detail: ns.stdout.trim().slice(0, 200) };
    }
    return { active: null, source: "unknown", detail: "netsh advfirewall failed" };
  }
  return { active: null, source: "unknown", detail: "Unsupported platform" };
}

async function getClamdServiceState() {
  const pl = process.platform;
  if (pl === "linux") {
    for (const unit of ["clamav-daemon", "clamav-clamd", "clamd"]) {
      const st = await execQuick("systemctl", ["is-active", unit]);
      if (st.ok && st.stdout.trim() === "active") {
        return { running: true, unit, method: "systemd" };
      }
    }
    return { running: false, unit: null, method: "systemd" };
  }
  if (pl === "darwin") {
    let pg = await execQuick("pgrep", ["-x", "clamd"]);
    if (pg.ok && pg.stdout.trim()) {
      return { running: true, unit: "clamd", method: "pgrep -x" };
    }
    pg = await execQuick("pgrep", ["-fl", "clamd"]);
    if (pg.ok && /clamd/i.test(pg.stdout || "")) {
      return { running: true, unit: "clamd", method: "pgrep" };
    }
    const brew = resolveHomebrewBin();
    const bl = await execQuick(brew, ["services", "list"]);
    if (bl.ok && /^\s*clamav\s+started\b/im.test(bl.stdout || "")) {
      return { running: true, unit: "clamav", method: "brew services" };
    }
    return { running: false, unit: null, method: "process" };
  }
  if (pl === "win32") {
    for (const name of ["ClamAV Scanner", "ClamD", "clamav-daemon"]) {
      const sc = await execQuick("sc", ["query", name]);
      if (sc.ok && /RUNNING/i.test(sc.stdout)) {
        return { running: true, unit: name, method: "sc" };
      }
    }
    return { running: false, unit: null, method: "sc" };
  }
  return { running: false, unit: null, method: "unknown" };
}

async function getRealtimeProtectionState() {
  const pl = process.platform;
  const monitor = realtimeState.running;
  const method = realtimeState.method;

  if (monitor) {
    const methodLabel = { fswatch: "fswatch (ESF)", inotifywait: "inotifywait", "node-fswatch": "Node.js watcher" };
    return {
      available: true,
      running: true,
      detail: `Built-in monitor active (${methodLabel[method] || method})`,
      unit: method,
    };
  }

  if (pl === "linux") {
    const which = await execQuick("which", ["clamonacc"]);
    if (which.ok && which.stdout.trim()) {
      for (const unit of ["clamav-clamonacc", "clamonacc"]) {
        const st = await execQuick("systemctl", ["is-active", unit]);
        if (st.ok && st.stdout.trim() === "active") {
          return { available: true, running: true, unit, detail: "systemd reports active" };
        }
      }
      const pg = await execQuick("pgrep", ["-x", "clamonacc"]);
      if (pg.ok && pg.stdout.trim()) {
        return { available: true, running: true, unit: "clamonacc", detail: "process running" };
      }
    }
  }

  const methodHint = pl === "darwin" ? "fswatch or built-in watcher" : pl === "win32" ? "built-in watcher" : "inotifywait or built-in watcher";
  return { available: true, running: false, detail: `Not active — start from the Real-time tab (${methodHint})` };
}

async function runClamdServiceAction(action) {
  if (!["start", "stop", "restart"].includes(action)) {
    return { ok: false, error: "Invalid action", terminalLogs: [] };
  }
  const pl = process.platform;
  if (pl === "linux") {
    const terminalLogs = [];
    const pk = await resolvePkexec();
    const attempts = [];
    for (const unit of ["clamav-daemon", "clamav-clamd", "clamd"]) {
      const rUser = await execService("systemctl", [action, unit]);
      terminalLogs.push(
        logFromExecService(`systemctl ${action} (${unit}, user)`, "systemctl", [action, unit], rUser),
      );
      if (rUser.ok) {
        return { ok: true, method: "systemctl (user)", unit, elevated: false, terminalLogs };
      }
      attempts.push(`user ${unit}: ${combineExecOutput(rUser) || "failed"}`);
      if (
        ELEVATE_SERVICES &&
        pk &&
        isLikelyPermissionFailure(combineExecOutput(rUser))
      ) {
        await new Promise((r) => setTimeout(r, BREW_RETRY_AFTER_PERMISSION_MS));
        const rPk = await execService(pk, ["systemctl", action, unit]);
        terminalLogs.push(
          logFromExecService(`pkexec systemctl ${action} (${unit})`, pk, ["systemctl", action, unit], rPk, {
            elevated: true,
          }),
        );
        if (rPk.ok) {
          return {
            ok: true,
            method: "pkexec systemctl (after permission failure — password prompt)",
            unit,
            elevated: true,
            terminalLogs,
          };
        }
        attempts.push(`pkexec ${unit}: ${combineExecOutput(rPk) || "failed"}`);
      }
    }
    const hint = !ELEVATE_SERVICES
      ? "Elevation is off (CLAMAV_GUI_NO_ELEVATE=1). Remove it to use pkexec, or run sudo systemctl … in a terminal."
      : pk
        ? "pkexec may have been canceled or polkit denied systemctl. Try: sudo systemctl start clamav-daemon"
        : "pkexec not found. Install policykit (pkexec) or run sudo systemctl … in a terminal.";
    return {
      ok: false,
      error: attempts.join("\n"),
      elevated: false,
      hint,
      terminalLogs,
    };
  }
  if (pl === "darwin") {
    const terminalLogs = [];
    const brewPath = (await resolveBrewPath()) || resolveHomebrewBin();
    const tryNames = ["clamav", "clamd"];
    let anyAdminRetry = false;

    const rb = async (args) => {
      const r = await runBrewDarwinFirstThenElevate(brewPath, args, { timeout: SERVICE_CMD_TIMEOUT_MS });
      if (Array.isArray(r.terminalLogs)) terminalLogs.push(...r.terminalLogs);
      if (r.brewUsedAdminRetry) anyAdminRetry = true;
      return r.code === 0;
    };

    if (action === "restart") {
      for (const name of tryNames) {
        if (await rb(["services", "restart", name])) {
          return {
            ok: true,
            method: anyAdminRetry ? "brew services restart (user then admin retry)" : "brew services restart (user)",
            unit: name,
            brew: brewPath,
            elevated: anyAdminRetry,
            terminalLogs,
          };
        }
      }
      for (const name of tryNames) {
        await rb(["services", "stop", name]);
      }
      for (const name of tryNames) {
        if (await rb(["services", "start", name])) {
          return {
            ok: true,
            method: anyAdminRetry ? "brew services stop+start (user then admin retry)" : "brew services stop+start (user)",
            unit: name,
            brew: brewPath,
            elevated: anyAdminRetry,
            terminalLogs,
          };
        }
      }
    } else {
      const brewCmd = action === "start" ? "start" : "stop";
      for (const name of tryNames) {
        if (await rb(["services", brewCmd, name])) {
          return {
            ok: true,
            method: anyAdminRetry ? `brew services ${brewCmd} (user then admin retry)` : `brew services ${brewCmd} (user)`,
            unit: name,
            brew: brewPath,
            elevated: anyAdminRetry,
            terminalLogs,
          };
        }
      }
    }

    return {
      ok: false,
      error: "brew services failed for clamav and clamd (including admin retry if a permission error triggered it).",
      brew: brewPath,
      elevated: anyAdminRetry,
      hint:
        "brew runs as your user first; wait for that attempt to finish. If macOS reported a permission problem, approve the one administrator dialog for a single retry. Do not use sudo brew as your default.",
      terminalLogs,
    };
  }
  if (pl === "win32") {
    const terminalLogs = [];
    const uac = async (cmdline) => {
      const r = await runWindowsElevatedCmdC(cmdline);
      terminalLogs.push(
        terminalLogEntry({
          label: `UAC (powershell RunAs): ${cmdline}`,
          argv: ["cmd", "/c", cmdline],
          stdout: r.stdout,
          stderr: r.stderr,
          code: r.ok ? 0 : 1,
          extra: { elevated: true },
        }),
      );
      return r;
    };
    const netCall = async (args, label) => {
      const r = await execService("net", args);
      terminalLogs.push(logFromExecService(label, "net", args, r));
      return r;
    };

    if (ELEVATE_SERVICES) {
      if (action === "restart") {
        await uac("net stop ClamD");
        let r = await uac("net start ClamD");
        if (r.ok) return { ok: true, method: "UAC + net", unit: "ClamD", elevated: true, terminalLogs };
        await uac('net stop "ClamAV Scanner"');
        r = await uac('net start "ClamAV Scanner"');
        if (r.ok) return { ok: true, method: "UAC + net", unit: "ClamAV Scanner", elevated: true, terminalLogs };
        return {
          ok: false,
          error: combineExecOutput(r) || "Elevated net restart failed for ClamD and ClamAV Scanner.",
          elevated: true,
          hint: "Approve the UAC prompt, or start the service from services.msc as Administrator.",
          terminalLogs,
        };
      }
      const net = action === "start" ? "start" : "stop";
      let r = await uac(`net ${net} ClamD`);
      if (r.ok) return { ok: true, method: "UAC + net", unit: "ClamD", elevated: true, terminalLogs };
      r = await uac(`net ${net} "ClamAV Scanner"`);
      if (r.ok) return { ok: true, method: "UAC + net", unit: "ClamAV Scanner", elevated: true, terminalLogs };
      return {
        ok: false,
        error: combineExecOutput(r) || "Elevated net command failed",
        elevated: true,
        hint: "Approve the UAC prompt. If the service name differs, use Services (services.msc).",
        terminalLogs,
      };
    }
    if (action === "restart") {
      await netCall(["stop", "ClamD"], "net stop ClamD");
      const b = await netCall(["start", "ClamD"], "net start ClamD");
      if (b.ok) return { ok: true, method: "net", unit: "ClamD", elevated: false, terminalLogs };
      await netCall(["stop", "ClamAV Scanner"], 'net stop "ClamAV Scanner"');
      const b2 = await netCall(["start", "ClamAV Scanner"], 'net start "ClamAV Scanner"');
      if (b2.ok) return { ok: true, method: "net", unit: "ClamAV Scanner", elevated: false, terminalLogs };
      return {
        ok: false,
        error: `${combineExecOutput(b)}\n${combineExecOutput(b2)}`,
        elevated: false,
        hint: "Run without elevation disabled, or run the app as Administrator.",
        terminalLogs,
      };
    }
    const net = action === "start" ? "start" : "stop";
    let r = await netCall([net, "ClamD"], `net ${net} ClamD`);
    if (r.ok) return { ok: true, method: "net", unit: "ClamD", elevated: false, terminalLogs };
    r = await netCall([net, "ClamAV Scanner"], `net ${net} ClamAV Scanner`);
    if (r.ok) return { ok: true, method: "net", unit: "ClamAV Scanner", elevated: false, terminalLogs };
    return {
      ok: false,
      error: combineExecOutput(r) || "net command failed",
      elevated: false,
      hint: "Windows often needs elevation for net start (UAC).",
      terminalLogs,
    };
  }
  return { ok: false, error: "Unsupported platform", terminalLogs: [] };
}

async function runRealtimeAction(action) {
  if (!["start", "stop"].includes(action)) {
    return { ok: false, error: "Invalid action", terminalLogs: [] };
  }
  if (process.platform !== "linux") {
    return {
      ok: false,
      error: "Real-time (clamonacc) control is only wired for Linux systemd",
      terminalLogs: [],
    };
  }
  const terminalLogs = [];
  const pk = await resolvePkexec();
  const attempts = [];
  for (const unit of ["clamav-clamonacc", "clamonacc"]) {
    const rUser = await execService("systemctl", [action, unit]);
    terminalLogs.push(
      logFromExecService(`systemctl ${action} (${unit}, user)`, "systemctl", [action, unit], rUser),
    );
    if (rUser.ok) return { ok: true, unit, elevated: false, terminalLogs };
    attempts.push(`user ${unit}: ${combineExecOutput(rUser) || "failed"}`);
    if (ELEVATE_SERVICES && pk && isLikelyPermissionFailure(combineExecOutput(rUser))) {
      await new Promise((r) => setTimeout(r, BREW_RETRY_AFTER_PERMISSION_MS));
      const rPk = await execService(pk, ["systemctl", action, unit]);
      terminalLogs.push(
        logFromExecService(`pkexec systemctl ${action} (${unit})`, pk, ["systemctl", action, unit], rPk, {
          elevated: true,
        }),
      );
      if (rPk.ok) return { ok: true, unit, elevated: true, terminalLogs };
      attempts.push(`pkexec ${unit}: ${combineExecOutput(rPk) || "failed"}`);
    }
  }
  return { ok: false, error: attempts.join("\n"), elevated: false, terminalLogs };
}

async function loadDefaultConf(which) {
  const name = which === "freshclam" ? "freshclam.conf" : "clamd.conf";
  const p = path.join(defaultsDir, name);
  return await fs.readFile(p, "utf8");
}

async function countFilesRecursive(root, { maxFiles, deadline }) {
  let count = 0;
  let st;
  try {
    st = await fs.stat(root);
  } catch {
    return { count: 1, partial: false };
  }
  if (!st.isDirectory()) return { count: 1, partial: false };
  let partial = false;
  const stack = [root];
  while (stack.length) {
    if (Date.now() > deadline || count >= maxFiles) {
      partial = true;
      break;
    }
    const dir = stack.pop();
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const ent of entries) {
      if (Date.now() > deadline) {
        return { count: Math.max(1, count), partial: true };
      }
      const p = path.join(dir, ent.name);
      if (ent.isDirectory()) stack.push(p);
      else if (ent.isFile()) {
        count++;
        if (count >= maxFiles) return { count, partial: true };
      }
    }
  }
  return { count: Math.max(1, count), partial };
}

async function countScanTargets(targetPath) {
  const st = await fs.stat(targetPath).catch(() => null);
  if (!st) return { total: 1, partial: false };
  if (!st.isDirectory()) return { total: 1, partial: false };
  const { count, partial } = await countFilesRecursive(targetPath, {
    maxFiles: 500_000,
    deadline: Date.now() + 12_000,
  });
  return { total: Math.max(1, count), partial };
}

function computeScanProgress(s) {
  if (s.status === "completed") return 100;
  if (s.status === "cancelled" || s.status === "error") return s.lastProgress ?? 0;
  if (s.totalFiles && !s.countPartial && s.totalFiles > 0) {
    return Math.min(99, Math.round((s.filesScanned / s.totalFiles) * 100));
  }
  const n = s.filesScanned;
  return Math.min(95, Math.round(8 + (1 - Math.exp(-n / 1800)) * 82));
}

function buildScanStatePayload(session) {
  const progress = computeScanProgress(session);
  session.lastProgress = progress;
  return {
    type: "state",
    scanId: session.id,
    status: session.status,
    mode: session.mode,
    targetLabel: session.targetLabel,
    targetPath: session.targetPath,
    filesScanned: session.filesScanned,
    totalFiles: session.totalFiles,
    countPartial: session.countPartial,
    progress,
    progressExact: !!(session.totalFiles && !session.countPartial),
    currentFile: session.currentFile,
    infectedCount: session.infectedCount,
    scanLines: session.scanLines.slice(-200),
    stdoutTail: tailString(session.stdout + session.stderr, 8000),
  };
}

function tailString(s, max) {
  if (s.length <= max) return s;
  return s.slice(-max);
}

function sseWrite(res, obj) {
  res.write(`data: ${JSON.stringify(obj)}\n\n`);
}

function broadcastScan(session, obj) {
  for (const res of session.sseClients) {
    try {
      sseWrite(res, obj);
    } catch {
      /* closed */
    }
  }
}

function pushScanState(session) {
  broadcastScan(session, buildScanStatePayload(session));
}

async function readHistoryFile() {
  try {
    const raw = await fs.readFile(HISTORY_FILE, "utf8");
    const j = JSON.parse(raw);
    return Array.isArray(j) ? j : [];
  } catch {
    return [];
  }
}

async function appendHistoryEntry(entry) {
  const prev = await readHistoryFile();
  prev.unshift(entry);
  await fs.mkdir(SCAN_ROOT, { recursive: true });
  await fs.writeFile(HISTORY_FILE, JSON.stringify(prev.slice(0, SCAN_HISTORY_MAX), null, 2), "utf8");
}

function parseScanOutputLine(line) {
  const t = line.trim();
  if (!t) return null;
  if (/^-+\s*SCAN SUMMARY/i.test(t)) return null;
  if (/^(Known viruses|Engine version|Scanned (dir|file)|Infected files|Data (scan|read)|Time):/i.test(t)) return null;
  if (/^LibClamAV/i.test(t)) return null;
  const scanningMatch = t.match(/^Scanning\s+(.+)$/);
  if (scanningMatch) return { kind: "scanning", filePath: scanningMatch[1].trim() };
  const m = t.match(/^(.+?):\s+(.+)$/);
  if (!m) return null;
  const filePath = m[1].trim();
  const rest = m[2].trim();
  if (/^OK$/i.test(rest) || /^Empty file/i.test(rest)) return { kind: "ok", filePath };
  if (/FOUND$/i.test(rest)) return { kind: "found", filePath, detail: rest };
  if (/Access denied|ERROR|Excluded|Can't access|Permission denied|lstat\(\) failed/i.test(rest))
    return { kind: "skip", filePath, detail: rest };
  return null;
}

const SCAN_LOG_MAX = 500;

function feedScanChunk(session, chunk) {
  session.lineBuf += chunk;
  const parts = session.lineBuf.split(/\r?\n/);
  session.lineBuf = parts.pop() || "";
  for (const line of parts) {
    const raw = line.trim();
    if (!raw) continue;
    const parsed = parseScanOutputLine(raw);
    if (parsed) {
      if (parsed.kind === "scanning") {
        session.currentFile = parsed.filePath;
      } else if (parsed.kind === "ok" || parsed.kind === "found" || parsed.kind === "skip") {
        session.filesScanned++;
        session.currentFile = parsed.filePath;
        session.scanLines.push({ file: parsed.filePath, status: parsed.kind, detail: parsed.detail || null });
      }
      if (parsed.kind === "found") {
        session.infectedCount++;
        session.findings.push(`${parsed.filePath}: ${parsed.detail}`);
      }
    }
    if (session.scanLines.length > SCAN_LOG_MAX) {
      session.scanLines = session.scanLines.slice(-SCAN_LOG_MAX);
    }
    const now = Date.now();
    const urgent = parsed?.kind === "found";
    if (urgent || now - (session.lastSsePush || 0) >= 75) {
      session.lastSsePush = now;
      pushScanState(session);
    }
  }
}

async function finishScanSession(session) {
  const endedAt = Date.now();
  const entry = {
    id: session.id,
    startedAt: session.startedAt,
    endedAt,
    mode: session.mode,
    targetLabel: session.targetLabel,
    targetPath: session.targetPath,
    status: session.status,
    exitCode: session.exitCode,
    exitSignal: session.exitSignal,
    filesScanned: session.filesScanned,
    infectedCount: session.infectedCount,
    infected: !!session.infected,
    spawnError: session.spawnError || null,
    findings: session.findings.slice(0, 200),
    logTail: tailString(session.stdout + session.stderr, 12_000),
  };
  try {
    await appendHistoryEntry(entry);
  } catch (e) {
    console.error("scan history write failed", e);
  }
  broadcastScan(session, {
    type: "done",
    ...buildScanStatePayload(session),
    exitCode: session.exitCode,
    exitSignal: session.exitSignal,
    spawnError: session.spawnError,
    findings: session.findings,
  });
  const t = setTimeout(() => scanSessions.delete(session.id), 120_000);
  t.unref?.();
}

async function runScanSession(scanId) {
  const session = scanSessions.get(scanId);
  if (!session) return;

  session.status = "preparing";
  pushScanState(session);

  try {
    let totalAll = 0;
    let partialAny = false;
    for (const t of session.targets) {
      const { total, partial } = await countScanTargets(t);
      totalAll += total;
      if (partial) partialAny = true;
    }
    session.totalFiles = totalAll;
    session.countPartial = partialAny;
    pushScanState(session);
  } catch {
    session.totalFiles = null;
    session.countPartial = true;
    pushScanState(session);
  }

  if (session.cancelRequested) {
    session.status = "cancelled";
    pushScanState(session);
    await finishScanSession(session);
    return;
  }

  session.status = "running";
  pushScanState(session);

  const scanArgs = buildClamscanArgs(session.targets);
  const child = spawn(CLAMSCAN_BIN, scanArgs, {
    cwd: SAFE_CWD,
    env: { ...process.env },
  });
  session.child = child;

  child.stdout?.on("data", (d) => {
    const s = d.toString();
    session.stdout += s;
    feedScanChunk(session, s);
  });
  child.stderr?.on("data", (d) => {
    const s = d.toString();
    session.stderr += s;
    feedScanChunk(session, s);
  });

  await new Promise((resolve) => {
    child.on("error", (e) => {
      session.spawnError = String(e.message || e);
      resolve();
    });
    child.on("close", (code, signal) => {
      session.exitCode = code;
      session.exitSignal = signal;
      resolve();
    });
  });

  session.child = null;
  if (session.lineBuf.trim()) {
    feedScanChunk(session, "\n");
  }

  if (session.cancelRequested || session.exitSignal === "SIGTERM") {
    session.status = "cancelled";
  } else if (session.spawnError) {
    session.status = "error";
    if (session.spawnError.includes("ENOENT")) {
      session.spawnError = "clamscan binary not found. Is ClamAV installed?";
    }
  } else if (session.exitCode === 0 || session.exitCode === 1) {
    session.status = "completed";
    session.infected = session.exitCode === 1;
  } else if (session.exitCode === 2) {
    session.status = "error";
    if (!session.spawnError) {
      session.spawnError = `Scanner error (exit 2). ${(session.stderr || "").slice(0, 300)}`;
    }
  } else {
    session.status = "error";
    if (!session.spawnError) {
      session.spawnError = `clamscan exited with code ${session.exitCode}. ${(session.stderr || "").slice(0, 300)}`;
    }
  }

  pushScanState(session);
  await finishScanSession(session);
}

// ─── Real-time file monitoring engine ─────────────────────────────────────────

const realtimeState = {
  running: false,
  method: null,         // "fswatch" | "clamonacc" | "fswatch-node" | "inotifywait"
  pid: null,
  watchedDirs: [],
  filesScanned: 0,
  threatsFound: 0,
  lastEvent: null,      // { file, status, detail, ts }
  events: [],           // ring buffer of last 200 events
  startedAt: null,
  error: null,
  child: null,          // internal, not serialised
  scanQueue: [],        // internal
  scanBusy: false,      // internal
  sseClients: new Set(),
};

const RT_EVENT_RING_SIZE = 200;
const RT_SCAN_CONCURRENCY = 2;

function rtPushEvent(evt) {
  realtimeState.events.push(evt);
  if (realtimeState.events.length > RT_EVENT_RING_SIZE) {
    realtimeState.events = realtimeState.events.slice(-RT_EVENT_RING_SIZE);
  }
  realtimeState.lastEvent = evt;
  for (const client of realtimeState.sseClients) {
    try { client.write(`data: ${JSON.stringify(evt)}\n\n`); } catch { /* ignore */ }
  }
}

function rtSnapshot() {
  return {
    running: realtimeState.running,
    method: realtimeState.method,
    watchedDirs: realtimeState.watchedDirs,
    filesScanned: realtimeState.filesScanned,
    threatsFound: realtimeState.threatsFound,
    lastEvent: realtimeState.lastEvent,
    startedAt: realtimeState.startedAt,
    error: realtimeState.error,
  };
}

async function rtScanFile(filePath) {
  if (!filePath || !fsSync.existsSync(filePath)) return;
  let st;
  try { st = fsSync.statSync(filePath); } catch { return; }
  if (st.isDirectory() || st.size === 0) return;

  realtimeState.filesScanned++;
  const evt = { file: filePath, status: "scanning", detail: null, ts: Date.now() };

  const bin = CLAMSCAN_BIN;
  if (!bin || !fsSync.existsSync(bin)) {
    evt.status = "error";
    evt.detail = "clamscan not found";
    rtPushEvent(evt);
    return;
  }

  const args = ["-v", "--stdout", "--no-summary"];
  try { fsSync.mkdirSync(QUARANTINE_DIR, { recursive: true }); } catch { /* ignore */ }
  args.push(`--move=${QUARANTINE_DIR}`);

  const confContent = readFileSafeSync(CLAMD_CONF);
  if (confContent) {
    const dbMatch = confContent.match(/^\s*DatabaseDirectory\s+(.+)$/im);
    if (dbMatch) {
      const dbDir = dbMatch[1].trim();
      if (fsSync.existsSync(dbDir)) args.push("--database", dbDir);
    }
  }

  args.push(filePath);

  try {
    const result = await runCmd(bin, args, { timeout: 60000 });
    const out = (result.stdout || "") + (result.stderr || "");
    if (result.code === 1 || /FOUND/i.test(out)) {
      evt.status = "threat";
      const m = out.match(/:\s*(.+)\s+FOUND/);
      evt.detail = m ? m[1].trim() : "Threat detected";
      realtimeState.threatsFound++;
    } else if (result.code === 0) {
      evt.status = "clean";
    } else {
      evt.status = "error";
      evt.detail = `exit ${result.code}: ${(result.stderr || "").slice(0, 200)}`;
    }
  } catch (e) {
    evt.status = "error";
    evt.detail = String(e).slice(0, 200);
  }
  evt.ts = Date.now();
  rtPushEvent(evt);
}

async function rtDrainQueue() {
  if (realtimeState.scanBusy) return;
  realtimeState.scanBusy = true;
  while (realtimeState.scanQueue.length > 0 && realtimeState.running) {
    const batch = realtimeState.scanQueue.splice(0, RT_SCAN_CONCURRENCY);
    await Promise.all(batch.map((f) => rtScanFile(f)));
  }
  realtimeState.scanBusy = false;
}

function rtEnqueueFile(filePath) {
  if (!realtimeState.running) return;
  const ext = path.extname(filePath).toLowerCase();
  const skipExts = new Set([".log", ".tmp", ".swp", ".lock", ".pid", ".sock"]);
  if (skipExts.has(ext)) return;
  const skipPaths = [QUARANTINE_DIR, "/proc", "/sys", "/dev"];
  if (skipPaths.some((p) => filePath.startsWith(p))) return;
  realtimeState.scanQueue.push(filePath);
  void rtDrainQueue();
}

function rtDefaultWatchDirs() {
  const home = os.homedir();
  const dirs = [
    path.join(home, "Downloads"),
    path.join(home, "Documents"),
    path.join(home, "Desktop"),
  ];
  if (process.platform === "darwin") {
    dirs.push(path.join(home, "Applications"));
  }
  if (process.platform === "win32") {
    const appData = process.env.APPDATA;
    if (appData) dirs.push(path.join(appData, "..\\Local\\Temp"));
  } else {
    dirs.push("/tmp");
  }
  return dirs.filter((d) => {
    try { return fsSync.statSync(d).isDirectory(); } catch { return false; }
  });
}

// --- macOS: fswatch backend (ESF-aware when available) ---
function rtStartFswatch(dirs) {
  const fswatchPath = ["/opt/homebrew/bin/fswatch", "/usr/local/bin/fswatch"]
    .find((p) => fsSync.existsSync(p));
  if (!fswatchPath) return null;

  const args = [
    "--recursive",
    "--event", "Created",
    "--event", "Updated",
    "--event", "MovedTo",
    "--event", "Renamed",
    "--batch-marker=---BATCH---",
    ...dirs,
  ];

  const child = spawn(fswatchPath, args, {
    cwd: SAFE_CWD,
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });

  let lineBuf = "";
  child.stdout.on("data", (chunk) => {
    lineBuf += chunk.toString();
    const lines = lineBuf.split("\n");
    lineBuf = lines.pop() || "";
    for (const line of lines) {
      const f = line.trim();
      if (!f || f === "---BATCH---") continue;
      rtEnqueueFile(f);
    }
  });

  child.on("error", (e) => {
    realtimeState.error = `fswatch error: ${e.message}`;
    rtStop();
  });

  child.on("exit", (code) => {
    if (realtimeState.running && realtimeState.method === "fswatch") {
      realtimeState.error = `fswatch exited unexpectedly (code ${code})`;
      realtimeState.running = false;
      realtimeState.child = null;
    }
  });

  return child;
}

// --- Linux: inotifywait backend ---
function rtStartInotifywait(dirs) {
  const bin = ["/usr/bin/inotifywait", "/usr/local/bin/inotifywait"]
    .find((p) => fsSync.existsSync(p));
  if (!bin) return null;

  const args = [
    "-m", "-r",
    "-e", "create,close_write,moved_to",
    "--format", "%w%f",
    ...dirs,
  ];

  const child = spawn(bin, args, {
    cwd: SAFE_CWD,
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });

  let lineBuf = "";
  child.stdout.on("data", (chunk) => {
    lineBuf += chunk.toString();
    const lines = lineBuf.split("\n");
    lineBuf = lines.pop() || "";
    for (const line of lines) {
      const f = line.trim();
      if (f) rtEnqueueFile(f);
    }
  });

  child.on("error", (e) => {
    realtimeState.error = `inotifywait error: ${e.message}`;
    rtStop();
  });

  child.on("exit", (code) => {
    if (realtimeState.running && realtimeState.method === "inotifywait") {
      realtimeState.error = `inotifywait exited unexpectedly (code ${code})`;
      realtimeState.running = false;
      realtimeState.child = null;
    }
  });

  return child;
}

// --- Windows / universal fallback: Node.js fs.watch ---
const nodeWatchers = [];

function rtStartNodeWatch(dirs) {
  for (const dir of dirs) {
    try {
      const w = fsSync.watch(dir, { recursive: true }, (eventType, filename) => {
        if (!filename) return;
        const full = path.join(dir, filename);
        if (eventType === "rename" || eventType === "change") {
          setTimeout(() => {
            try {
              if (fsSync.existsSync(full) && fsSync.statSync(full).isFile()) {
                rtEnqueueFile(full);
              }
            } catch { /* file may have been deleted */ }
          }, 200);
        }
      });
      nodeWatchers.push(w);
    } catch { /* dir may not be watchable */ }
  }
  return nodeWatchers.length > 0;
}

function rtStopNodeWatchers() {
  while (nodeWatchers.length) {
    try { nodeWatchers.pop().close(); } catch { /* ignore */ }
  }
}

// --- Orchestrator ---
function rtStart(customDirs) {
  if (realtimeState.running) return { ok: false, error: "Already running" };

  const dirs = customDirs?.length ? customDirs : rtDefaultWatchDirs();
  if (!dirs.length) return { ok: false, error: "No valid directories to watch" };

  realtimeState.watchedDirs = dirs;
  realtimeState.filesScanned = 0;
  realtimeState.threatsFound = 0;
  realtimeState.events = [];
  realtimeState.lastEvent = null;
  realtimeState.error = null;
  realtimeState.scanQueue = [];
  realtimeState.scanBusy = false;
  realtimeState.startedAt = Date.now();

  const pl = process.platform;

  if (pl === "darwin") {
    const child = rtStartFswatch(dirs);
    if (child) {
      realtimeState.running = true;
      realtimeState.method = "fswatch";
      realtimeState.child = child;
      realtimeState.pid = child.pid;
      rtPushEvent({ file: null, status: "info", detail: `Real-time monitoring started (fswatch, ${dirs.length} dirs)`, ts: Date.now() });
      return { ok: true, method: "fswatch", dirs };
    }
    // fallback to node watcher
  }

  if (pl === "linux") {
    const child = rtStartInotifywait(dirs);
    if (child) {
      realtimeState.running = true;
      realtimeState.method = "inotifywait";
      realtimeState.child = child;
      realtimeState.pid = child.pid;
      rtPushEvent({ file: null, status: "info", detail: `Real-time monitoring started (inotifywait, ${dirs.length} dirs)`, ts: Date.now() });
      return { ok: true, method: "inotifywait", dirs };
    }
  }

  // Universal fallback: Node.js fs.watch
  const ok = rtStartNodeWatch(dirs);
  if (ok) {
    realtimeState.running = true;
    realtimeState.method = "node-fswatch";
    realtimeState.child = null;
    realtimeState.pid = null;
    rtPushEvent({ file: null, status: "info", detail: `Real-time monitoring started (Node.js watcher, ${dirs.length} dirs)`, ts: Date.now() });
    return { ok: true, method: "node-fswatch", dirs };
  }

  return { ok: false, error: "No file watching backend available" };
}

function rtStop() {
  if (!realtimeState.running && !realtimeState.child && nodeWatchers.length === 0) {
    return { ok: false, error: "Not running" };
  }

  if (realtimeState.child) {
    try { realtimeState.child.kill("SIGTERM"); } catch { /* ignore */ }
    realtimeState.child = null;
  }
  rtStopNodeWatchers();

  realtimeState.running = false;
  realtimeState.pid = null;
  realtimeState.scanQueue = [];

  rtPushEvent({ file: null, status: "info", detail: "Real-time monitoring stopped", ts: Date.now() });

  for (const client of realtimeState.sseClients) {
    try { client.write(`data: ${JSON.stringify({ type: "stopped" })}\n\n`); client.end(); } catch { /* ignore */ }
  }
  realtimeState.sseClients.clear();

  return { ok: true };
}

// --- API ---

app.get("/api/install/status", async (_req, res) => {
  try {
    const status = await gatherInstallStatus();
    res.json({ ok: true, ...status });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e.message || e) });
  }
});

app.post("/api/install/step", async (req, res) => {
  const step = typeof req.body?.step === "string" ? req.body.step : "";
  const brewPath = await resolveBrewPath();

  try {
    if (step === "brew-install") {
      if (process.platform !== "darwin" || !brewPath) {
        return res.status(400).json({
          ok: false,
          step,
          message: "Automatic install requires macOS and Homebrew in PATH or a standard location.",
        });
      }
      const r = await runBrewDarwinFirstThenElevate(brewPath, ["install", "clamav"], { timeout: 900_000 });
      return res.json({
        ok: r.code === 0,
        step,
        code: r.code,
        stdout: r.stdout,
        stderr: r.stderr,
        brewUsedAdminRetry: !!r.brewUsedAdminRetry,
        terminalLogs: r.terminalLogs || [],
      });
    }

    if (step === "ensure-config") {
      if (process.platform !== "darwin" || !brewPath) {
        return res.status(400).json({
          ok: false,
          step,
          message: "Config helper requires macOS and Homebrew.",
        });
      }
      const out = await ensureHomebrewClamdLayout(brewPath, CLAMD_CONF);
      return res.json({
        ok: true,
        step,
        ...out,
        terminalLogs: [
          terminalLogEntry({
            label: "ensure-config (filesystem + clamd.conf)",
            argv: ["ensureHomebrewClamdLayout", CLAMD_CONF],
            stdout: `wrote=${out.wrote} listenerConfigured=${out.listenerConfigured} prefix=${out.prefix}`,
            stderr: "",
            code: 0,
          }),
        ],
      });
    }

    if (step === "start-service") {
      if (process.platform !== "darwin" || !brewPath) {
        return res.status(400).json({
          ok: false,
          step,
          message: "Start service requires macOS and Homebrew.",
        });
      }
      const r = await runBrewDarwinFirstThenElevate(brewPath, ["services", "start", "clamav"], {
        timeout: 120_000,
      });
      return res.json({
        ok: r.code === 0,
        step,
        code: r.code,
        stdout: r.stdout,
        stderr: r.stderr,
        brewUsedAdminRetry: !!r.brewUsedAdminRetry,
        terminalLogs: r.terminalLogs || [],
      });
    }

    if (step === "fix-brew-permissions") {
      if (process.platform !== "darwin" || !brewPath) {
        return res.status(400).json({ ok: false, step, message: "Only needed on macOS with Homebrew." });
      }
      const prefix = await homebrewPrefixFromBrew(brewPath) || "/opt/homebrew";
      const username = os.userInfo().username;
      const dirs = [
        path.join(prefix, "Cellar", "clamav"),
        path.join(prefix, "opt", "clamav"),
        path.join(prefix, "var", "homebrew", "linked", "clamav"),
      ].filter((d) => fsSync.existsSync(d));
      const scriptBody = `
set +e
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
USER=${bashSingleQuote(username)}
${dirs.map((d) => `chown -R "$USER:admin" ${bashSingleQuote(d)} 2>/dev/null`).join("\n")}
chown -R "$USER:admin" ${bashSingleQuote(path.join(prefix, "etc", "clamav"))} 2>/dev/null
chown -R "$USER:admin" ${bashSingleQuote(path.join(prefix, "var", "run", "clamav"))} 2>/dev/null
chown -R "$USER:admin" ${bashSingleQuote(path.join(prefix, "var", "lib", "clamav"))} 2>/dev/null
echo "clamav-gui: Restored Homebrew ClamAV ownership to $USER:admin"
exit 0
`;
      const r = await runDarwinAdminBash(scriptBody);
      return res.json({
        ok: r.ok,
        step,
        terminalLogs: [
          terminalLogEntry({
            label: "fix-brew-permissions (chown Cellar/clamav back to your user)",
            argv: ["chown", "-R", `${username}:admin`, "…clamav dirs…"],
            stdout: r.stdout,
            stderr: r.stderr,
            code: r.ok ? 0 : 1,
            extra: { via: "osascript: do shell script … with administrator privileges" },
          }),
        ],
      });
    }

    return res.status(400).json({ ok: false, error: `Unknown step: ${step}` });
  } catch (e) {
    res.status(500).json({ ok: false, step, error: String(e.message || e) });
  }
});

app.post("/api/install/uninstall", async (_req, res) => {
  try {
    if (process.platform === "darwin") {
      const brewPath = await resolveBrewPath();
      if (!brewPath) {
        return res.status(400).json({
          ok: false,
          message: "Homebrew not found; cannot uninstall via this app.",
          terminalLogs: [],
        });
      }
      const out = await uninstallHomebrewClamav(brewPath);
      return res.json({ ...out, terminalLogs: terminalLogsFromUninstallPhases(out.phases) });
    }
    if (process.platform === "linux") {
      const out = await uninstallLinuxClamav();
      return res.json({ ...out, terminalLogs: terminalLogsFromUninstallPhases(out.phases) });
    }
    return res.status(501).json({
      ok: false,
      message:
        "Automated uninstall is not available on Windows from this app. Use Settings → Apps or the ClamAV uninstaller.",
      phases: [],
      terminalLogs: [],
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e.message || e), phases: [], terminalLogs: [] });
  }
});

app.get("/api/health", async (_req, res) => {
  const clamd = await runCmd(CLAMDSCAN_BIN, ["--version"]).catch((e) => ({
    code: 1,
    stdout: "",
    stderr: String(e),
  }));
  const fresh = await runCmd(FRESHCLAM_BIN, ["--version"]).catch((e) => ({
    code: 1,
    stdout: "",
    stderr: String(e),
  }));
  const freshOnPath = !(fresh.stderr || "").includes("ENOENT");
  const [pingResult, firewall, clamdService, realtime, clamdConn] = await Promise.all([
    tryClamdPing(),
    getFirewallStatus(),
    getClamdServiceState(),
    getRealtimeProtectionState(),
    parseClamdConnectionFromDisk(),
  ]);
  const daemonResponding = pingResult.ok;
  res.json({
    ok: true,
    clamav: {
      clamdscanInstalled: clamd.code === 0 || clamd.stdout.includes("ClamAV"),
      freshclamInstalled: freshOnPath || fresh.code === 0 || String(fresh.stdout + fresh.stderr).includes("ClamAV"),
      daemonResponding,
      pingMethod: pingResult.method || null,
      pingError: daemonResponding ? null : pingResult.detail || null,
    },
    firewall,
    clamdService: {
      ...clamdService,
      socketOk: daemonResponding,
    },
    realtimeProtection: realtime,
    realtimeMonitor: rtSnapshot(),
    paths: {
      clamdConf: CLAMD_CONF,
      freshclamConf: FRESHCLAM_CONF,
      scanRoot: SCAN_ROOT,
      clamdUnixSocket: clamdConn.unixSocket || null,
      clamdTcp: clamdConn.tcpPort != null ? `${clamdConn.tcpHost}:${clamdConn.tcpPort}` : null,
    },
    scan: {
      quickDirs: standardScanDirs(),
      fullPath: fullSystemScanRoot(),
      customHint:
        "Absolute paths must be inside your home folder.",
    },
    quarantine: {
      dir: QUARANTINE_DIR,
      enabled: true,
    },
  });
});

app.get("/api/config/:which", async (req, res) => {
  const which = req.params.which;
  const file = which === "freshclam" ? FRESHCLAM_CONF : CLAMD_CONF;
  if (which !== "clamd" && which !== "freshclam") {
    return res.status(400).json({ error: "Invalid config name" });
  }
  const r = await readFileSafe(file);
  if (!r.ok) return res.status(404).json({ error: r.error });
  res.json({ path: file, content: r.content });
});

app.put("/api/config/:which", async (req, res) => {
  const which = req.params.which;
  const file = which === "freshclam" ? FRESHCLAM_CONF : CLAMD_CONF;
  if (which !== "clamd" && which !== "freshclam") {
    return res.status(400).json({ error: "Invalid config name" });
  }
  const { content } = req.body || {};
  if (typeof content !== "string") {
    return res.status(400).json({ error: "Body must include string content" });
  }
  try {
    const { backup } = await writeFileSafe(file, content);
    res.json({ ok: true, path: file, backup });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

app.post("/api/config/reset", async (req, res) => {
  const which = req.body?.which;
  const scope = which === "clamd" || which === "freshclam" ? which : "both";
  try {
    const out = {};
    if (scope === "both" || scope === "clamd") {
      const content = await loadDefaultConf("clamd");
      const { backup } = await writeFileSafe(CLAMD_CONF, content);
      out.clamd = { path: CLAMD_CONF, backup };
    }
    if (scope === "both" || scope === "freshclam") {
      const content = await loadDefaultConf("freshclam");
      const { backup } = await writeFileSafe(FRESHCLAM_CONF, content);
      out.freshclam = { path: FRESHCLAM_CONF, backup };
    }
    res.json({ ok: true, ...out });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

app.get("/api/actions/freshclam-stream", async (req, res) => {
  if (freshclamStreamBusy) {
    return res.status(429).json({ error: "Another definition update is already running." });
  }
  freshclamStreamBusy = true;
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  if (typeof res.flushHeaders === "function") res.flushHeaders();
  sseWrite(res, { type: "progress", progress: 5, indeterminate: true });

  let lastPct = 5;
  const bump = () => {
    lastPct = Math.min(90, lastPct + (lastPct < 35 ? 4 : lastPct < 70 ? 2 : 1));
    sseWrite(res, { type: "progress", progress: lastPct, indeterminate: false });
  };
  const bumpTimer = setInterval(bump, 700);

  const sendLine = (text) => {
    const pctMatch = text.match(/(\d{1,3})\s*%/);
    if (pctMatch) {
      const p = Math.min(95, Math.max(lastPct, Number(pctMatch[1])));
      lastPct = p;
      sseWrite(res, { type: "progress", progress: p, indeterminate: false });
    }
    sseWrite(res, { type: "line", text: text.slice(0, 2000) });
  };

  const child = spawn(FRESHCLAM_BIN, [], { cwd: SAFE_CWD, env: { ...process.env } });
  let stdout = "";
  let stderr = "";
  let lineBuf = "";
  const feedLines = (chunk) => {
    lineBuf += chunk;
    const parts = lineBuf.split(/\r?\n/);
    lineBuf = parts.pop() || "";
    for (const line of parts) {
      if (line.trim()) sendLine(line);
    }
  };

  child.stdout?.on("data", (d) => {
    const s = d.toString();
    stdout += s;
    feedLines(s);
  });
  child.stderr?.on("data", (d) => {
    const s = d.toString();
    stderr += s;
    feedLines(s);
  });

  let clientGone = false;
  const stopBump = () => clearInterval(bumpTimer);
  const releaseBusy = () => {
    freshclamStreamBusy = false;
  };

  req.on("close", () => {
    clientGone = true;
    stopBump();
    try {
      child.kill("SIGTERM");
    } catch {
      /* ignore */
    }
    releaseBusy();
  });

  child.on("close", async (code, signal) => {
    stopBump();
    if (lineBuf.trim()) sendLine(lineBuf);

    const fullOut = stdout;
    const fullErr = stderr;
    const userExit = typeof code === "number" ? code : signal ? 1 : 1;
    let terminalLogs = [
      logFromRunCmd("freshclam (streamed run, your user)", FRESHCLAM_BIN, [], {
        code: userExit,
        stdout: fullOut,
        stderr: fullErr,
      }),
    ];
    let finalCode = userExit;
    let mergedOut = fullOut;
    let mergedErr = fullErr;
    let finalOk = code === 0;

    if (
      !clientGone &&
      typeof code === "number" &&
      code !== 0 &&
      ELEVATE_SERVICES &&
      isLikelyPermissionFailure(`${fullOut}\n${fullErr}`)
    ) {
      sendLine(
        "Permission error detected; retrying freshclam with elevated privileges (you may be prompted for a password).",
      );
      await new Promise((r) => setTimeout(r, BREW_RETRY_AFTER_PERMISSION_MS));
      const second = await runElevatedFreshclamOnly();
      const extra = second.via ? { via: second.via } : {};
      terminalLogs.push(
        terminalLogEntry({
          label: "freshclam (streamed run, elevated retry)",
          argv: ["freshclam"],
          stdout: second.stdout,
          stderr: second.stderr,
          code: second.ok ? 0 : 1,
          extra,
        }),
      );
      finalOk = second.ok;
      finalCode = second.ok ? 0 : 1;
      mergedOut = [fullOut, second.stdout].filter(Boolean).join("\n");
      mergedErr = [fullErr, second.stderr].filter(Boolean).join("\n");
    }

    releaseBusy();

    if (clientGone || res.writableEnded) {
      return;
    }

    const outS = tailString(mergedOut, 12000);
    const outE = tailString(mergedErr, 12000);
    sseWrite(res, {
      type: "done",
      ok: finalOk,
      code: finalCode,
      stdout: outS,
      stderr: outE,
      terminalLogs,
      usedElevation: terminalLogs.length > 1,
    });
    try {
      res.end();
    } catch {
      /* ignore */
    }
  });

  child.on("error", (e) => {
    stopBump();
    releaseBusy();
    if (!clientGone && !res.writableEnded) {
      sseWrite(res, { type: "done", ok: false, code: -1, error: String(e.message || e) });
      try {
        res.end();
      } catch {
        /* ignore */
      }
    }
  });
});

app.post("/api/actions/freshclam", async (_req, res) => {
  const r = await runFreshclamWithOptionalElevation();
  res.json({
    ok: r.ok,
    code: r.code,
    stdout: r.stdout,
    stderr: r.stderr,
    usedElevation: r.usedElevation,
    terminalLogs: r.terminalLogs,
  });
});

app.post("/api/actions/clamd-service", async (req, res) => {
  const action = req.body?.action;
  if (!["start", "stop", "restart"].includes(action)) {
    return res.status(400).json({ ok: false, error: "action must be start, stop, or restart" });
  }
  const r = await runClamdServiceAction(action);
  res.json(r);
});

app.post("/api/actions/realtime", async (req, res) => {
  const action = req.body?.action;
  if (!["start", "stop"].includes(action)) {
    return res.status(400).json({ ok: false, error: "action must be start or stop", terminalLogs: [] });
  }
  const r = await runRealtimeAction(action);
  res.json(r);
});

app.post("/api/actions/firewall", async (req, res) => {
  const action = req.body?.action;
  if (!["on", "off"].includes(action)) {
    return res.status(400).json({ ok: false, error: "action must be on or off" });
  }
  const pl = process.platform;
  try {
    if (pl === "darwin") {
      const flag = action === "on" ? "--setglobalstate" : "--setglobalstate";
      const val = action === "on" ? "on" : "off";
      const r = await runDarwinAdminBash(
        `/usr/libexec/ApplicationFirewall/socketfilterfw ${flag} ${val}`,
        { timeout: 15_000 },
      );
      const combined = `${r.stdout}\n${r.stderr}`.trim();
      const ok = r.ok || /enabled|disabled/i.test(combined);
      return res.json({ ok, detail: combined });
    }
    if (pl === "linux") {
      const pk = await resolvePkexec();
      if (!pk) return res.json({ ok: false, detail: "pkexec not found" });
      const ufwR = await runCmd(pk, ["ufw", action === "on" ? "enable" : "disable"], { timeout: 15_000 });
      if (ufwR.code === 0) return res.json({ ok: true, detail: (ufwR.stdout + ufwR.stderr).trim() });
      const fwR = await runCmd(pk, ["firewall-cmd", action === "on" ? "--reload" : "--complete-reload"], { timeout: 15_000 });
      return res.json({ ok: fwR.code === 0, detail: (fwR.stdout + fwR.stderr).trim() });
    }
    if (pl === "win32") {
      const val = action === "on" ? "on" : "off";
      const r = await runWindowsElevatedCmdC(`netsh advfirewall set allprofiles state ${val}`, { timeout: 15_000 });
      return res.json({ ok: r.ok, detail: (r.stdout + r.stderr).trim() });
    }
    res.json({ ok: false, detail: "Unsupported platform" });
  } catch (e) {
    res.status(500).json({ ok: false, detail: String(e.message || e) });
  }
});

app.post("/api/actions/restart-clamd", async (_req, res) => {
  if (process.platform === "darwin") {
    const brewPath = await resolveBrewPath();
    if (brewPath) {
      const attempts = [
        ["services", "restart", "clamav"],
        ["services", "stop", "clamav"],
        ["services", "start", "clamav"],
      ];
      const log = [];
      const terminalLogs = [];
      let ok = false;
      for (const args of attempts) {
        const r = await runBrewDarwinFirstThenElevate(brewPath, args, { timeout: 120_000 });
        if (Array.isArray(r.terminalLogs)) terminalLogs.push(...r.terminalLogs);
        log.push({
          args: args.join(" "),
          code: r.code,
          brewUsedAdminRetry: !!r.brewUsedAdminRetry,
          stderr: r.stderr?.slice?.(0, 2000),
        });
        if (r.code === 0 && (args[1] === "restart" || args[1] === "start")) {
          ok = true;
          break;
        }
      }
      if (ok) {
        return res.json({ ok: true, method: "brew-services", log, terminalLogs });
      }
      return res.json({
        ok: false,
        method: "brew-services",
        log,
        terminalLogs,
        message:
          "brew services could not restart ClamAV. Try Auto-install → Configure daemon, then Start daemon. brew runs as your user first; a permission error triggers one administrator retry.",
      });
    }
    return res.json({
      ok: false,
      method: "none",
      message: "Homebrew not found. Install Homebrew or restart clamd from the Dashboard service controls.",
      terminalLogs: [],
    });
  }

  const r = await execService("service", ["clamav-daemon", "restart"]);
  const entry = logFromExecService(
    "service clamav-daemon restart",
    "service",
    ["clamav-daemon", "restart"],
    r,
  );
  if (r.ok) {
    return res.json({ ok: true, method: "service", terminalLogs: [entry] });
  }
  return res.json({
    ok: false,
    method: "none",
    message:
      "No service manager restarted clamd. On Linux use systemctl or service clamav-daemon restart. On macOS use Homebrew and the Auto-install tab.",
    terminalLogs: [entry],
  });
});

app.get("/api/scan/stream", (req, res) => {
  const scanId = typeof req.query.id === "string" ? req.query.id : "";
  const session = scanSessions.get(scanId);
  if (!session) {
    return res.status(404).json({ error: "Scan not found" });
  }
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  if (typeof res.flushHeaders === "function") res.flushHeaders();
  session.sseClients.add(res);
  sseWrite(res, buildScanStatePayload(session));
  const keepalive = setInterval(() => {
    try {
      res.write(": keepalive\n\n");
    } catch {
      clearInterval(keepalive);
    }
  }, 25_000);
  req.on("close", () => {
    clearInterval(keepalive);
    session.sseClients.delete(res);
  });
});

app.post("/api/scan/start", async (req, res) => {
  const { target, targets, mode } = resolveScanRequest(req.body || {});
  if (!target || !targets || targets.length === 0) {
    return res.status(400).json({
      error:
        "Invalid path. Standard scan covers Downloads, Documents, Desktop. Custom: use an absolute path under your home directory.",
    });
  }
  for (const t of targets) {
    try {
      await fs.access(t);
    } catch {
      return res.status(404).json({ error: `Path not found: ${t}` });
    }
  }
  const scanId = crypto.randomUUID();
  const session = {
    id: scanId,
    mode,
    targets,
    targetPath: targets.join(", "),
    targetLabel: scanTargetLabel(mode, target),
    status: "queued",
    child: null,
    totalFiles: null,
    countPartial: false,
    filesScanned: 0,
    infectedCount: 0,
    currentFile: "",
    sseClients: new Set(),
    stdout: "",
    stderr: "",
    lineBuf: "",
    findings: [],
    scanLines: [],
    startedAt: Date.now(),
    cancelRequested: false,
    spawnError: null,
    exitCode: null,
    exitSignal: null,
    infected: false,
    lastProgress: 0,
    lastSsePush: 0,
  };
  scanSessions.set(scanId, session);
  res.json({
    scanId,
    mode,
    targetPath: target,
    targetLabel: session.targetLabel,
  });
  runScanSession(scanId).catch(async (e) => {
    const s = scanSessions.get(scanId);
    if (!s) return;
    s.status = "error";
    s.spawnError = String(e.message || e);
    pushScanState(s);
    await finishScanSession(s);
  });
});

app.post("/api/scan/cancel", (req, res) => {
  const id = req.body?.id;
  if (typeof id !== "string" || !id) {
    return res.status(400).json({ error: "id is required" });
  }
  const session = scanSessions.get(id);
  if (!session) {
    return res.status(404).json({ error: "Scan not found" });
  }
  session.cancelRequested = true;
  if (session.child) {
    try {
      session.child.kill("SIGTERM");
    } catch {
      /* ignore */
    }
  }
  res.json({ ok: true });
});

app.get("/api/scan/history", async (_req, res) => {
  try {
    const items = await readHistoryFile();
    res.json({ items });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

app.post("/api/scan", async (req, res) => {
  const { target, mode } = resolveScanRequest(req.body || {});
  if (!target) {
    return res.status(400).json({
      error:
        "Invalid path. Quick scan uses your scan folder. Custom: use a subpath there, or an absolute path under your home directory or scan folder.",
    });
  }
  try {
    await fs.access(target);
  } catch {
    return res.status(404).json({ error: "Path not found" });
  }
  try {
    const scanArgs = await buildClamdscanScanArgs(target);
    const { stdout, stderr, code } = await runCmd(CLAMDSCAN_BIN, scanArgs, {
      timeout: 3_600_000,
    });
    res.json({
      ok: code === 0 || code === 1,
      code,
      stdout,
      stderr,
      infected: code === 1,
      mode,
      target,
    });
  } catch (e) {
    const msg = String(e.message || e);
    const isEnoent = msg.includes("ENOENT") || msg.includes("not found");
    res.status(isEnoent ? 502 : 500).json({
      ok: false,
      error: isEnoent
        ? "clamdscan binary not found. Make sure ClamAV is installed."
        : `Scan failed: ${msg}`,
      mode,
      target,
    });
  }
});

app.get("/api/quarantine", async (_req, res) => {
  try {
    await fs.mkdir(QUARANTINE_DIR, { recursive: true });
    const entries = await fs.readdir(QUARANTINE_DIR);
    const items = [];
    for (const name of entries) {
      if (name.startsWith(".")) continue;
      const full = path.join(QUARANTINE_DIR, name);
      try {
        const st = await fs.stat(full);
        items.push({
          name,
          path: full,
          size: st.size,
          quarantinedAt: st.mtimeMs,
        });
      } catch { /* skip */ }
    }
    items.sort((a, b) => b.quarantinedAt - a.quarantinedAt);
    res.json({ dir: QUARANTINE_DIR, items });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

app.post("/api/quarantine/delete", async (req, res) => {
  const name = req.body?.name;
  if (!name || typeof name !== "string") {
    return res.status(400).json({ ok: false, error: "name is required" });
  }
  if (name.includes("/") || name.includes("\\") || name === ".." || name === ".") {
    return res.status(400).json({ ok: false, error: "Invalid filename" });
  }
  const full = path.join(QUARANTINE_DIR, name);
  if (!full.startsWith(path.resolve(QUARANTINE_DIR) + path.sep) && full !== path.resolve(QUARANTINE_DIR)) {
    return res.status(400).json({ ok: false, error: "Path escapes quarantine" });
  }
  try {
    await fs.unlink(full);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e.message || e) });
  }
});

app.post("/api/quarantine/restore", async (req, res) => {
  const name = req.body?.name;
  const destination = req.body?.destination;
  if (!name || typeof name !== "string") {
    return res.status(400).json({ ok: false, error: "name is required" });
  }
  if (name.includes("/") || name.includes("\\") || name === ".." || name === ".") {
    return res.status(400).json({ ok: false, error: "Invalid filename" });
  }
  const src = path.join(QUARANTINE_DIR, name);
  const home = os.homedir();
  const dest = destination
    ? path.resolve(String(destination))
    : path.join(home, "Desktop", name);
  if (!dest.startsWith(home + path.sep) && dest !== home) {
    return res.status(400).json({ ok: false, error: "Destination must be under your home directory" });
  }
  try {
    await fs.mkdir(path.dirname(dest), { recursive: true });
    await fs.rename(src, dest);
    res.json({ ok: true, restoredTo: dest });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e.message || e) });
  }
});

app.post("/api/quarantine/delete-all", async (_req, res) => {
  try {
    const entries = await fs.readdir(QUARANTINE_DIR);
    let deleted = 0;
    for (const name of entries) {
      if (name.startsWith(".")) continue;
      try {
        await fs.unlink(path.join(QUARANTINE_DIR, name));
        deleted++;
      } catch { /* skip */ }
    }
    res.json({ ok: true, deleted });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e.message || e) });
  }
});

function jobLineIndices(lines) {
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trim();
    if (t && !t.startsWith("#")) out.push(i);
  }
  return out;
}

app.get("/api/cron", async (_req, res) => {
  if (process.platform === "win32") {
    return cronUnsupported(res);
  }
  try {
    const { stdout, stderr } = await execFileAsync("crontab", crontabArgv(["-l"]), {
      maxBuffer: 2 * 1024 * 1024,
      cwd: SAFE_CWD,
    });
    const lines = stdout.split("\n");
    const indices = jobLineIndices(lines);
    const jobs = indices.map((lineIdx, id) => ({
      id,
      line: lines[lineIdx],
      lineIndex: lineIdx,
    }));
    res.json({ user: CRON_USER, jobs, raw: stdout, stderr: stderr || "" });
  } catch (e) {
    if (e.code === 1 && (!e.stdout || String(e.stdout).trim() === "")) {
      return res.json({ user: CRON_USER, jobs: [], raw: "", stderr: "" });
    }
    res.status(500).json({ error: String(e.message || e), stderr: e.stderr });
  }
});

app.post("/api/cron", async (req, res) => {
  if (process.platform === "win32") {
    return cronUnsupported(res);
  }
  const { schedule, command, comment } = req.body || {};
  if (typeof schedule !== "string" || typeof command !== "string") {
    return res.status(400).json({ error: "schedule and command are required strings" });
  }
  if (!/^\S+\s+\S+\s+\S+\s+\S+\s+\S+/.test(schedule.trim())) {
    return res.status(400).json({ error: "schedule must be five cron fields (minute hour dom month dow)" });
  }
  let current = "";
  try {
    const r = await execFileAsync("crontab", crontabArgv(["-l"]), { maxBuffer: 2 * 1024 * 1024, cwd: SAFE_CWD });
    current = r.stdout || "";
  } catch {
    current = "";
  }
  const prefix = comment ? `# ${String(comment).replace(/\n/g, " ")}\n` : "";
  const line = `${prefix}${schedule.trim()} ${command.trim()}\n`;
  const next = current.endsWith("\n") || current === "" ? current + line : `${current}\n${line}`;
  const child = spawn("crontab", crontabArgv(["-"]), { cwd: SAFE_CWD, stdio: ["pipe", "pipe", "pipe"] });
  child.stdin.write(next);
  child.stdin.end();
  let err = "";
  child.stderr.on("data", (d) => {
    err += d.toString();
  });
  await new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (c) => (c === 0 ? resolve() : reject(new Error(err || `exit ${c}`))));
  });
  res.json({ ok: true });
});

app.delete("/api/cron/:id", async (req, res) => {
  if (process.platform === "win32") {
    return cronUnsupported(res);
  }
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 0) {
    return res.status(400).json({ error: "Invalid job id" });
  }
  let raw = "";
  try {
    const r = await execFileAsync("crontab", crontabArgv(["-l"]), { maxBuffer: 2 * 1024 * 1024, cwd: SAFE_CWD });
    raw = r.stdout || "";
  } catch {
    return res.status(404).json({ error: "No crontab" });
  }
  const lines = raw.split("\n");
  const indices = jobLineIndices(lines);
  const lineIdx = indices[id];
  if (lineIdx === undefined) return res.status(404).json({ error: "Job not found" });

  let removeStart = lineIdx;
  let removeCount = 1;
  if (lineIdx > 0) {
    const prev = lines[lineIdx - 1].trim();
    if (prev.startsWith("#") && !/^#(PATH|MAIL|SHELL)=/i.test(prev)) {
      removeStart = lineIdx - 1;
      removeCount = 2;
    }
  }
  lines.splice(removeStart, removeCount);
  const next = lines.join("\n");
  const finalCrontab = next === "" ? "\n" : next.endsWith("\n") ? next : `${next}\n`;
  const child = spawn("crontab", crontabArgv(["-"]), { cwd: SAFE_CWD, stdio: ["pipe", "pipe", "pipe"] });
  child.stdin.write(finalCrontab);
  child.stdin.end();
  let err = "";
  child.stderr.on("data", (d) => {
    err += d.toString();
  });
  await new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (c) => (c === 0 ? resolve() : reject(new Error(err || `exit ${c}`))));
  });
  res.json({ ok: true });
});

// ─── Real-time monitoring API ─────────────────────────────────────────────────

app.get("/api/realtime/status", (_req, res) => {
  res.json(rtSnapshot());
});

app.post("/api/realtime/start", (req, res) => {
  const dirs = req.body?.dirs;
  const r = rtStart(Array.isArray(dirs) && dirs.length ? dirs : undefined);
  res.json(r);
});

app.post("/api/realtime/stop", (_req, res) => {
  const r = rtStop();
  res.json(r);
});

app.get("/api/realtime/events", (_req, res) => {
  res.json({ events: realtimeState.events });
});

app.get("/api/realtime/stream", (req, res) => {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });
  res.write(`data: ${JSON.stringify({ type: "snapshot", ...rtSnapshot() })}\n\n`);
  realtimeState.sseClients.add(res);
  req.on("close", () => { realtimeState.sseClients.delete(res); });
});

app.use(
  express.static(clientDist, {
    etag: false,
    setHeaders(res, filePath) {
      if (filePath.endsWith(".html")) {
        res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
      }
    },
  }),
);
app.get("*", (_req, res) => {
  res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
  res.sendFile(path.join(clientDist, "index.html"));
});

async function main() {
  await fs.mkdir(SCAN_ROOT, { recursive: true });
  await fs.mkdir(QUARANTINE_DIR, { recursive: true });
  app.listen(PORT, BIND_HOST, () => {
    console.log(`ClamAV GUI listening on ${BIND_HOST}:${PORT}`);
  });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
