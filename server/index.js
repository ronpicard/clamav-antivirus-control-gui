import express from "express";
import cors from "cors";
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

function runCmd(cmd, args, opts = {}) {
  const { env: envExtra, timeout, ...spawnOpts } = opts;
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      ...spawnOpts,
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
    child.on("error", reject);
    child.on("close", (code) => {
      resolve({ code, stdout, stderr });
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

function resolveScanTarget(userPath) {
  const normalized = path.normalize(userPath || "").replace(/^(\.\.(\/|\\|$))+/, "");
  const full = path.resolve(SCAN_ROOT, normalized);
  const root = path.resolve(SCAN_ROOT);
  if (!full.startsWith(root + path.sep) && full !== root) {
    return null;
  }
  return full;
}

// --- API ---

app.get("/api/health", async (_req, res) => {
  const clamd = await runCmd("clamdscan", ["--version"]).catch((e) => ({
    code: 1,
    stdout: "",
    stderr: String(e),
  }));
  const fresh = await runCmd("freshclam", ["--version"]).catch((e) => ({
    code: 1,
    stdout: "",
    stderr: String(e),
  }));
  const ping = await runCmd("clamdscan", ["/bin/true"]).catch((e) => ({
    code: 1,
    stdout: "",
    stderr: String(e),
  }));
  res.json({
    ok: true,
    clamav: {
      clamdscanInstalled: clamd.code === 0 || clamd.stdout.includes("ClamAV"),
      freshclamInstalled: fresh.code === 0 || fresh.stdout.includes("ClamAV"),
      daemonResponding: ping.code === 0 || /OK|Empty file/i.test(ping.stdout + ping.stderr),
    },
    paths: { clamdConf: CLAMD_CONF, freshclamConf: FRESHCLAM_CONF, scanRoot: SCAN_ROOT },
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

app.post("/api/actions/freshclam", async (_req, res) => {
  const { stdout, stderr, code } = await runCmd("freshclam", [], { timeout: 600_000 });
  res.json({ ok: code === 0, code, stdout, stderr });
});

app.post("/api/actions/restart-clamd", async (_req, res) => {
  try {
    await execFileAsync("service", ["clamav-daemon", "restart"]);
    res.json({ ok: true, method: "service" });
  } catch {
    res.json({
      ok: false,
      method: "none",
      message:
        "No service manager restarted clamd. Quit and reopen this app, or restart the ClamAV service from your system tools.",
    });
  }
});

app.post("/api/scan", async (req, res) => {
  const target = resolveScanTarget(req.body?.path || ".");
  if (!target) {
    return res.status(400).json({ error: `Path must stay under ${SCAN_ROOT}` });
  }
  try {
    await fs.access(target);
  } catch {
    return res.status(404).json({ error: "Path not found" });
  }
  const { stdout, stderr, code } = await runCmd("clamdscan", ["--fdpass", "-v", target], {
    timeout: 3_600_000,
  });
  res.json({
    ok: code === 0 || code === 1,
    code,
    stdout,
    stderr,
    infected: code === 1,
  });
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
    const r = await execFileAsync("crontab", crontabArgv(["-l"]), { maxBuffer: 2 * 1024 * 1024 });
    current = r.stdout || "";
  } catch {
    current = "";
  }
  const prefix = comment ? `# ${String(comment).replace(/\n/g, " ")}\n` : "";
  const line = `${prefix}${schedule.trim()} ${command.trim()}\n`;
  const next = current.endsWith("\n") || current === "" ? current + line : `${current}\n${line}`;
  const child = spawn("crontab", crontabArgv(["-"]), { stdio: ["pipe", "pipe", "pipe"] });
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
    const r = await execFileAsync("crontab", crontabArgv(["-l"]), { maxBuffer: 2 * 1024 * 1024 });
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
  const child = spawn("crontab", crontabArgv(["-"]), { stdio: ["pipe", "pipe", "pipe"] });
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

app.use(express.static(clientDist));
app.get("*", (_req, res) => {
  res.sendFile(path.join(clientDist, "index.html"));
});

async function main() {
  await fs.mkdir(SCAN_ROOT, { recursive: true });
  app.listen(PORT, BIND_HOST, () => {
    console.log(`ClamAV GUI listening on ${BIND_HOST}:${PORT}`);
  });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
