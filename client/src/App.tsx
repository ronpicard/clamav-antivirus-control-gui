import { useCallback, useEffect, useRef, useState } from "react";
import { applyGuidedValues, guideFieldsFor, parseGuidedValues } from "./clamavConfigGuide";

type Health = {
  ok: boolean;
  clamav: {
    clamdscanInstalled: boolean;
    freshclamInstalled: boolean;
    daemonResponding: boolean;
    pingMethod?: string | null;
    pingError?: string | null;
  };
  firewall?: { active: boolean | null; source: string; detail: string };
  clamdService?: {
    running: boolean;
    unit: string | null;
    method: string;
    socketOk: boolean;
  };
  realtimeProtection?: { available: boolean; running: boolean; detail?: string; unit?: string };
  paths: {
    clamdConf: string;
    freshclamConf: string;
    scanRoot: string;
    clamdUnixSocket?: string | null;
    clamdTcp?: string | null;
  };
  scan?: {
    quickDirs: string[];
    fullPath: string;
    customHint: string;
  };
  quarantine?: {
    dir: string;
    enabled: boolean;
  };
};

type InstallStatus = {
  ok: boolean;
  platform: string;
  canAutomate: boolean;
  brew: { path: string | null; version: string | null; clamavInstalled: boolean };
  paths: {
    homebrewPrefix: string | null;
    clamdConf: string;
    confExists: boolean;
    listenerConfigured: boolean;
  };
  binaries: { clamdscanOk: boolean; freshclamOk: boolean };
  manualSteps: { title: string; command: string }[];
  uninstall?: {
    canAutomated: boolean;
    manualSteps: { title: string; command: string }[];
  };
};

type CronJob = { id: number; line: string; lineIndex: number };

export type TerminalLogEntry = {
  label?: string;
  argv?: string[];
  stdout?: string;
  stderr?: string;
  code?: number;
  ok?: boolean;
  via?: string;
  elevated?: boolean;
  brewUsedAdminRetry?: boolean;
};

const api = (path: string, init?: RequestInit) => fetch(path, init);

function TerminalOutputPanel({ logs }: { logs: TerminalLogEntry[] }) {
  if (!logs.length) return null;
  return (
    <div className="terminal-output-panel" style={{ marginTop: "0.75rem" }}>
      <p className="section-label" style={{ marginBottom: "0.5rem" }}>
        Terminal output (commands run)
      </p>
      <div className="terminal-output-list">
        {logs.map((log, i) => {
          const cmdline =
            log.argv && log.argv.length > 0
              ? log.argv.map((a) => (/\s/.test(a) ? JSON.stringify(a) : a)).join(" ")
              : log.label || "—";
          return (
            <details key={i} className="terminal-log-block" open={i >= logs.length - 2}>
              <summary className="terminal-log-summary">
                <span className={`terminal-exit-pill ${log.ok ? "ok" : "bad"}`}>
                  exit {typeof log.code === "number" ? log.code : "—"}
                </span>
                <code className="terminal-cmd-line">{cmdline}</code>
                {log.label && log.argv?.length ? <span className="terminal-log-note"> — {log.label}</span> : null}
                {log.via ? <span className="terminal-log-note"> ({log.via})</span> : null}
              </summary>
              <div className="terminal-streams">
                {log.stderr ? (
                  <div className="terminal-stream">
                    <span className="term-stream-label">stderr</span>
                    <pre className="terminal-pre">{log.stderr}</pre>
                  </div>
                ) : null}
                {log.stdout ? (
                  <div className="terminal-stream">
                    <span className="term-stream-label">stdout</span>
                    <pre className="terminal-pre">{log.stdout}</pre>
                  </div>
                ) : null}
                {!log.stderr && !log.stdout ? (
                  <p className="hint" style={{ margin: "0.35rem 0 0" }}>
                    (no stdout/stderr captured)
                  </p>
                ) : null}
              </div>
            </details>
          );
        })}
      </div>
    </div>
  );
}

function PrivilegeBanner() {
  return (
    <div
      className="card"
      style={{
        marginBottom: "0.9rem",
        padding: "0.65rem 0.95rem",
        fontSize: "0.82rem",
        lineHeight: 1.45,
        borderColor: "var(--border)",
        background: "var(--surface2)",
      }}
      role="note"
    >
      <strong>Passwords and privileges:</strong> Homebrew is <strong>never</strong> started with{" "}
      <code>sudo brew</code>. Each <code>brew</code> command runs as <em>your user</em> first. If macOS reports
      a permission error, the app shows the <strong>administrator password</strong> dialog for a single retry.
      For <strong>service start/stop</strong>, the retry uses <code>launchctl</code> (not <code>sudo brew</code>)
      to load a system LaunchDaemon — this avoids Homebrew taking root ownership of Cellar paths. Linux{" "}
      <code>systemctl</code> runs as your user first, then <code>pkexec</code> only after a permission failure.
      Windows may show UAC. <strong>freshclam</strong> definition updates follow the same user-first pattern.
    </div>
  );
}

const TABS = [
  ["home", "Dashboard", "📊", "See what is working and refresh ClamAV"],
  ["auto-install", "Auto-install", "📦", "Install ClamAV — guided on Mac + Homebrew"],
  ["scan", "Scan", "🔎", "Scan files with live progress"],
  ["quarantine", "Quarantine", "🔒", "View and manage quarantined threats"],
  ["cron", "Schedules", "⏰", "Automate updates and scans (Mac/Linux)"],
  ["config", "Config", "⚙️", "Edit clamd and freshclam settings"],
  ["instructions", "Instructions", "📖", "Install ClamAV and use this app"],
] as const;

type ScanSessionState = {
  activeScanId: string | null;
  live: ScanStreamState | null;
  scanErr: string | null;
  pendingStart: boolean;
};

const EMPTY_SCAN_SESSION: ScanSessionState = {
  activeScanId: null,
  live: null,
  scanErr: null,
  pendingStart: false,
};

export default function App() {
  const [tab, setTab] = useState<(typeof TABS)[number][0]>("home");
  const [health, setHealth] = useState<Health | null>(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [scanSession, setScanSession] = useState<ScanSessionState>(EMPTY_SCAN_SESSION);

  const refresh = useCallback(async (silent?: boolean) => {
    if (!silent) setLoading(true);
    setErr(null);
    try {
      const r = await api("/api/health");
      if (!r.ok) throw new Error(await r.text());
      setHealth(await r.json());
    } catch (e) {
      setErr(String(e));
    } finally {
      if (!silent) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return (
    <>
      <header className="app-header">
        <div className="brand-row">
          <div className="brand-icon" aria-hidden>
            🛡️
          </div>
          <div>
            <h1>ClamAV Control</h1>
            <p className="subtitle">
              A simple panel for ClamAV on your computer: status, definition updates, config files, scans, and
              schedules (where supported).
            </p>
          </div>
        </div>
      </header>

      <div className="nav-shell">
        <nav className="tabs" aria-label="Main sections">
          {TABS.map(([id, label, emoji, title]) => (
            <button
              key={id}
              type="button"
              className={`tab ${tab === id ? "active" : ""}`}
              onClick={() => setTab(id)}
              title={title}
              aria-current={tab === id ? "page" : undefined}
            >
              <span className="tab-emoji" aria-hidden>
                {emoji}
              </span>
              {label}
            </button>
          ))}
        </nav>
      </div>

      <PrivilegeBanner />

      {err && (
        <div className="card card-error" role="alert">
          <h2 style={{ color: "var(--danger)", marginBottom: "0.5rem" }}>Cannot reach the app</h2>
          <p style={{ margin: 0, color: "var(--muted)", fontSize: "0.9rem" }}>{err}</p>
          <button type="button" className="btn btn-primary" style={{ marginTop: "1rem" }} onClick={refresh}>
            Try again
          </button>
        </div>
      )}

      <div className="panel-wrap" key={tab === "scan" ? "scan-persistent" : tab}>
        {tab === "home" && <Dashboard health={health} loading={loading} onRefresh={refresh} />}
        {tab === "auto-install" && <AutoInstallPanel health={health} onRefreshAll={refresh} />}
        {tab === "quarantine" && <QuarantinePanel />}
        {tab === "cron" && <CronPanel />}
        {tab === "config" && <ConfigPanel />}
        {tab === "instructions" && <InstructionsPanel />}
      </div>
      <div style={tab === "scan" ? undefined : { display: "none" }}>
        <div className="panel-wrap">
          <ScanPanel health={health} session={scanSession} setSession={setScanSession} onRefresh={refresh} />
        </div>
      </div>
    </>
  );
}

function Dashboard({
  health,
  loading,
  onRefresh,
}: {
  health: Health | null;
  loading: boolean;
  onRefresh: (silent?: boolean) => void | Promise<void>;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [log, setLog] = useState("");
  const [defProgress, setDefProgress] = useState(0);
  const [defStreaming, setDefStreaming] = useState(false);
  const [svcBusy, setSvcBusy] = useState(false);
  const [svcBanner, setSvcBanner] = useState<{ ok: boolean; text: string } | null>(null);
  const [cmdLogs, setCmdLogs] = useState<TerminalLogEntry[]>([]);
  const freshEsRef = useRef<EventSource | null>(null);
  const logPreRef = useRef<HTMLPreElement | null>(null);

  useEffect(() => {
    const el = logPreRef.current;
    if (!el || !log) return;
    el.scrollTop = el.scrollHeight;
  }, [log]);

  useEffect(() => {
    if (!svcBanner?.ok) return;
    if (health?.clamav?.daemonResponding) return;
    const id = window.setInterval(() => void onRefresh(true), 2000);
    const stop = window.setTimeout(() => window.clearInterval(id), 30000);
    return () => {
      window.clearInterval(id);
      window.clearTimeout(stop);
    };
  }, [svcBanner?.ok, health?.clamav?.daemonResponding, onRefresh]);

  const runFreshclam = () => {
    freshEsRef.current?.close();
    setLog("");
    setCmdLogs([]);
    setDefProgress(5);
    setDefStreaming(true);
    setBusy("Updating virus definitions…");
    const es = new EventSource("/api/actions/freshclam-stream");
    freshEsRef.current = es;
    es.onmessage = (ev) => {
      try {
        const m = JSON.parse(ev.data) as {
          type: string;
          progress?: number;
          text?: string;
          ok?: boolean;
          code?: number;
          stdout?: string;
          stderr?: string;
          error?: string;
        };
        if (m.type === "progress" && typeof m.progress === "number") {
          setDefProgress(m.progress);
        }
        if (m.type === "line" && m.text) {
          setLog((prev) => (prev + m.text + "\n").slice(-12000));
        }
        if (m.type === "done") {
          es.close();
          freshEsRef.current = null;
          setDefStreaming(false);
          setBusy(null);
          setDefProgress((p) => (m.ok ? 100 : p));
          const tl: TerminalLogEntry[] = [];
          if (Array.isArray((m as { terminalLogs?: TerminalLogEntry[] }).terminalLogs)) {
            tl.push(...(m as { terminalLogs: TerminalLogEntry[] }).terminalLogs);
          } else if (m.stdout || m.stderr || typeof m.code === "number") {
            tl.push({
              label: "freshclam",
              argv: ["freshclam"],
              stdout: m.stdout || "",
              stderr: m.stderr || "",
              code: typeof m.code === "number" ? m.code : m.ok ? 0 : 1,
              ok: !!m.ok,
            });
          }
          setCmdLogs(tl);
          setLog((prev) => prev + `\n--- finished (code ${m.code ?? "?"}) ---\n`);
          void onRefresh(true);
        }
      } catch {
        setLog((p) => p + "\n(parse error in stream)\n");
      }
    };
    es.onerror = () => {
      es.close();
      freshEsRef.current = null;
      setDefStreaming(false);
      setBusy(null);
      setLog((p) => p + "\n(Stream ended or disconnected.)\n");
    };
  };

  const restartClamd = async () => {
    setBusy("Restarting scanner service…");
    setLog("");
    setCmdLogs([]);
    try {
      const r = await api("/api/actions/restart-clamd", { method: "POST" });
      const j = (await r.json()) as { terminalLogs?: TerminalLogEntry[]; message?: string; log?: unknown[] };
      setCmdLogs(Array.isArray(j.terminalLogs) ? j.terminalLogs : []);
      setLog(j.message ? String(j.message) : "");
    } catch (e) {
      setLog(String(e));
    } finally {
      setBusy(null);
      void onRefresh(true);
    }
  };

  const clamdServiceAction = async (action: "start" | "stop" | "restart") => {
    setSvcBusy(true);
    setSvcBanner(null);
    setLog("");
    setCmdLogs([]);
    try {
      const r = await api("/api/actions/clamd-service", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action }),
      });
      const j = (await r.json()) as {
        ok?: boolean;
        error?: string;
        hint?: string;
        method?: string;
        unit?: string;
        brew?: string;
        terminalLogs?: TerminalLogEntry[];
      };
      setCmdLogs(Array.isArray(j.terminalLogs) ? j.terminalLogs : []);
      if (!r.ok) {
        setSvcBanner({
          ok: false,
          text: j.error || `HTTP ${r.status}`,
        });
        void onRefresh(true);
        return;
      }
      if (j.ok) {
        setSvcBanner({
          ok: true,
          text: `Command succeeded (${j.method ?? "?"}${j.unit ? `: ${j.unit}` : ""}). Watching daemon status for ~30s — keep this tab open.`,
        });
        [0, 1500, 3000, 5000, 8000, 12000, 20000].forEach((ms) =>
          window.setTimeout(() => void onRefresh(true), ms),
        );
      } else {
        const detail = [j.error, j.hint].filter(Boolean).join("\n\n");
        setSvcBanner({ ok: false, text: detail || "Start/stop failed (see log below)." });
        void onRefresh(true);
      }
    } catch (e) {
      setLog(String(e));
      setSvcBanner({ ok: false, text: String(e) });
      void onRefresh(true);
    } finally {
      setSvcBusy(false);
    }
  };

  const realtimeAction = async (action: "start" | "stop") => {
    setSvcBusy(true);
    setSvcBanner(null);
    setLog("");
    setCmdLogs([]);
    try {
      const r = await api("/api/actions/realtime", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action }),
      });
      const j = (await r.json()) as { ok?: boolean; error?: string; terminalLogs?: TerminalLogEntry[] };
      setCmdLogs(Array.isArray(j.terminalLogs) ? j.terminalLogs : []);
      if (j.ok) {
        setSvcBanner({ ok: true, text: "Real-time service command succeeded." });
        void onRefresh(true);
        window.setTimeout(() => void onRefresh(true), 1500);
      } else {
        setSvcBanner({ ok: false, text: j.error || "Command failed." });
        void onRefresh(true);
      }
    } catch (e) {
      setLog(String(e));
      setSvcBanner({ ok: false, text: String(e) });
      void onRefresh(true);
    } finally {
      setSvcBusy(false);
    }
  };

  const firewallAction = async (action: "on" | "off") => {
    setSvcBusy(true);
    setSvcBanner(null);
    try {
      const r = await api("/api/actions/firewall", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action }),
      });
      const j = (await r.json()) as { ok?: boolean; detail?: string };
      if (j.ok) {
        setSvcBanner({ ok: true, text: `Firewall ${action === "on" ? "enabled" : "disabled"}.` });
      } else {
        setSvcBanner({ ok: false, text: j.detail || "Firewall command failed." });
      }
      void onRefresh(true);
      window.setTimeout(() => void onRefresh(true), 1500);
    } catch (e) {
      setSvcBanner({ ok: false, text: String(e) });
      void onRefresh(true);
    } finally {
      setSvcBusy(false);
    }
  };

  const c = health?.clamav;
  const fw = health?.firewall;
  const svc = health?.clamdService;
  const rt = health?.realtimeProtection;

  const fwOk = fw?.active === true;
  const fwOff = fw?.active === false;
  const fwUnknown = fw?.active === null || fw?.active === undefined;

  const daemonResponding = !!c?.daemonResponding;
  const serviceRunning = !!svc?.running;
  const daemonPillClass = daemonResponding ? "ok" : serviceRunning ? "wait" : "wait";
  const daemonPillLabel = daemonResponding
    ? "on / responding"
    : serviceRunning
      ? "service on, daemon not answering yet"
      : "off or not responding";
  const daemonPillTitle = [
    daemonPillLabel,
    c?.pingMethod,
    c?.pingError && !daemonResponding ? `Error: ${c.pingError}` : "",
  ]
    .filter(Boolean)
    .join(" — ");

  return (
    <div className="card">
      <p className="section-label">Overview</p>
      <h2>Is ClamAV ready?</h2>
      {loading && (
        <>
          <p className="hint" style={{ marginBottom: "0.75rem" }}>
            <span className="spinner-inline" aria-hidden />
            Checking your system…
          </p>
          <div className="skeleton-block" aria-hidden />
        </>
      )}
      {!loading && health && (
        <>
          <div className="status-grid">
            <span className={`status-pill ${c?.freshclamInstalled ? "ok" : "bad"}`}>
              <span className="dot" aria-hidden />
              Definition updater
              <span className="status-pill-muted">freshclam</span>
            </span>
            <span className={`status-pill ${c?.clamdscanInstalled ? "ok" : "bad"}`}>
              <span className="dot" aria-hidden />
              Scanner CLI
              <span className="status-pill-muted">clamdscan</span>
            </span>
            <span className={`status-pill ${daemonPillClass}`} title={daemonPillTitle || undefined}>
              <span className="dot" aria-hidden />
              Scanner daemon
              <span className="status-pill-muted">{daemonPillLabel}</span>
            </span>
            <span
              className={`status-pill ${fwOk ? "ok" : fwOff ? "bad" : "wait"}`}
              title={fw?.detail}
            >
              <span className="dot" aria-hidden />
              Firewall
              <span className="status-pill-muted">
                {fwOk ? "on" : fwOff ? "off" : fwUnknown ? "unknown" : "—"}
              </span>
            </span>
            <span
              className={`status-pill ${rt?.running ? "ok" : rt?.available ? "bad" : "wait"}`}
              title={rt?.detail}
            >
              <span className="dot" aria-hidden />
              Real-time
              <span className="status-pill-muted">
                {rt?.running ? "on" : rt?.available ? "off" : "n/a"}
              </span>
            </span>
          </div>
          <p className="section-label">Firewall</p>
          <p className="hint" style={{ marginBottom: "0.65rem" }}>
            <strong>{fw?.source || "System firewall"}:</strong>{" "}
            {fwOk ? "Enabled" : fwOff ? "Disabled" : "Unknown"}
            {fw?.detail ? ` — ${fw.detail}` : ""}
          </p>
          <div className="action-grid" style={{ marginBottom: "1rem" }}>
            <button
              type="button"
              className="btn btn-primary"
              disabled={svcBusy || !!busy || fwOk}
              onClick={() => void firewallAction("on")}
            >
              ▶ Enable firewall
            </button>
            <button
              type="button"
              className="btn btn-ghost"
              disabled={svcBusy || !!busy || fwOff}
              onClick={() => void firewallAction("off")}
            >
              ■ Disable firewall
            </button>
          </div>

          <p className="section-label">Scanner daemon</p>
          <p className="hint" style={{ marginBottom: "0.65rem" }}>
            Service:{" "}
            <strong>{svc?.running ? `running (${svc.unit || svc.method})` : "not running"}</strong>
            {" · "}
            Daemon ping:{" "}
            <strong>{daemonResponding ? "OK" : "no response"}</strong>
            {health.paths.clamdUnixSocket && (
              <>
                <br />
                Socket used for ping/scan: <code>{health.paths.clamdUnixSocket}</code>
              </>
            )}
            {!daemonResponding && c?.pingError && (
              <>
                <br />
                <span style={{ color: "var(--danger)" }}>Detail: {c.pingError}</span>
              </>
            )}
            <br />
            <strong>macOS (Homebrew):</strong> start/stop uses <code>brew services</code> as <em>your user</em> only
            — no <code>sudo brew</code>. <strong>Linux:</strong> <code>pkexec</code> may ask for your password for{" "}
            <code>systemctl</code>. <strong>Windows:</strong> UAC may appear for <code>net start</code> /{" "}
            <code>net stop</code>.
          </p>
          {svcBusy && (
            <p className="hint" style={{ marginBottom: "0.65rem" }}>
              <span className="spinner-inline" aria-hidden />
              Running system command — wait for it to finish. If a password dialog appears (macOS admin,
              Linux pkexec, Windows UAC), approve it; the app retries with privilege only when needed.
            </p>
          )}
          {svcBanner && (
            <div
              className="svc-action-banner"
              role="status"
              style={{
                marginBottom: "0.85rem",
                padding: "0.75rem 0.9rem",
                borderRadius: 10,
                fontSize: "0.82rem",
                lineHeight: 1.5,
                whiteSpace: "pre-wrap",
                border: `1px solid ${svcBanner.ok ? "rgba(61, 217, 160, 0.45)" : "rgba(224, 93, 93, 0.5)"}`,
                background: svcBanner.ok ? "rgba(61, 217, 160, 0.1)" : "rgba(224, 93, 93, 0.1)",
                color: svcBanner.ok ? "#9ff5d2" : "#ffb4b4",
              }}
            >
              {svcBanner.ok ? "✓ " : "✕ "}
              {svcBanner.text}
            </div>
          )}
          <div className="action-grid" style={{ marginBottom: "1rem" }}>
            <button
              type="button"
              className="btn btn-primary"
              disabled={svcBusy || !!busy}
              onClick={() => void clamdServiceAction("start")}
            >
              ▶ Start daemon
            </button>
            <button
              type="button"
              className="btn btn-ghost"
              disabled={svcBusy || !!busy}
              onClick={() => void clamdServiceAction("stop")}
            >
              ■ Stop daemon
            </button>
            <button
              type="button"
              className="btn btn-ghost"
              disabled={svcBusy || !!busy}
              onClick={() => void clamdServiceAction("restart")}
            >
              ⟳ Restart (service)
            </button>
          </div>

          <p className="section-label">Real-time protection</p>
          {rt?.available ? (
            <>
              <p className="hint" style={{ marginBottom: "0.65rem" }}>
                On-access scanning (<code>clamonacc</code>):{" "}
                <strong>{rt.running ? "Running" : "Stopped"}</strong>
                {rt.detail ? ` — ${rt.detail}` : ""}
              </p>
              <div className="action-grid" style={{ marginBottom: "1rem" }}>
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={svcBusy || !!busy || rt.running}
                  onClick={() => realtimeAction("start")}
                >
                  ▶ Turn on
                </button>
                <button
                  type="button"
                  className="btn btn-ghost"
                  disabled={svcBusy || !!busy || !rt.running}
                  onClick={() => realtimeAction("stop")}
                >
                  ■ Turn off
                </button>
              </div>
            </>
          ) : (
            <p className="hint" style={{ marginBottom: "0.85rem" }}>
              {rt?.detail || "On-access scanning (clamonacc) is not available on this platform."}{" "}
              Use scheduled scans from the Scan tab instead.
            </p>
          )}

          <div className="steps">
            <div className="step-card">
              <div className="step-num">1</div>
              <strong>Install ClamAV</strong>
              Use Homebrew, your Linux packages, or the Windows installer so the tools above show green.
            </div>
            <div className="step-card">
              <div className="step-num">2</div>
              <strong>Add files to scan</strong>
              Copy them into your scan folder (path below). The app creates it if needed.
            </div>
            <div className="step-card">
              <div className="step-num">3</div>
              <strong>Use Scan and Config</strong>
              Run scans from the Scan tab or tweak configs when you know what you are changing.
            </div>
          </div>

          <p className="hint" style={{ marginBottom: "0.65rem" }}>
            <strong>Your scan folder</strong>
          </p>
          <div className="path-chip">{health.paths.scanRoot}</div>

          <p className="section-label" style={{ marginTop: "1.15rem" }}>
            Actions
          </p>
          <div className="action-grid">
            <button
              type="button"
              className="btn btn-primary"
              disabled={!!busy || defStreaming}
              onClick={() => void onRefresh(true)}
            >
              {busy && !defStreaming ? (
                <>
                  <span className="spinner-inline" aria-hidden />
                  Working…
                </>
              ) : (
                "↻ Refresh status"
              )}
            </button>
            <button type="button" className="btn btn-ghost" disabled={!!busy || defStreaming} onClick={runFreshclam}>
              ⬇ Update definitions now
            </button>
            <button type="button" className="btn btn-ghost" disabled={!!busy || defStreaming} onClick={restartClamd}>
              ⟳ Restart daemon (legacy)
            </button>
          </div>
          {defStreaming && (
            <div className="scan-progress-wrap" style={{ marginTop: "1rem" }}>
              <div className="scan-progress-meta">
                <span>
                  <strong>{defProgress}%</strong> definitions
                </span>
                <span>Downloading / updating…</span>
              </div>
              <div className="scan-progress-track">
                <div className="scan-progress-fill" style={{ width: `${defProgress}%` }} />
              </div>
            </div>
          )}
          {busy && (
            <p className="hint">
              <span className="spinner-inline" aria-hidden />
              {busy}
            </p>
          )}
          <TerminalOutputPanel logs={cmdLogs} />
          {log && (
            <pre ref={logPreRef} className="log-box log-box-live">
              {log}
            </pre>
          )}
        </>
      )}
    </div>
  );
}

function ConfigPanel() {
  const [which, setWhich] = useState<"clamd" | "freshclam">("clamd");
  const [content, setContent] = useState("");
  const [guidedValues, setGuidedValues] = useState<Record<string, string>>({});
  const [editorMode, setEditorMode] = useState<"guided" | "raw">("guided");
  const [msg, setMsg] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const fields = guideFieldsFor(which);

  const load = useCallback(async () => {
    setLoading(true);
    setMsg(null);
    try {
      const r = await api(`/api/config/${which}`);
      if (!r.ok) throw new Error(await r.text());
      const j = await r.json();
      setContent(j.content);
      setGuidedValues(parseGuidedValues(j.content, guideFieldsFor(which)));
    } catch (e) {
      setMsg(String(e));
    } finally {
      setLoading(false);
    }
  }, [which]);

  useEffect(() => {
    load();
  }, [load]);

  const mergeGuidedIntoContent = () => applyGuidedValues(content, fields, guidedValues);

  const switchToRaw = () => {
    if (editorMode === "guided") {
      setContent(mergeGuidedIntoContent());
    }
    setEditorMode("raw");
  };

  const switchToGuided = () => {
    setGuidedValues(parseGuidedValues(content, fields));
    setEditorMode("guided");
  };

  const save = async () => {
    setLoading(true);
    setMsg(null);
    const bodyContent = editorMode === "guided" ? mergeGuidedIntoContent() : content;
    try {
      const r = await api(`/api/config/${which}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content: bodyContent }),
      });
      if (!r.ok) throw new Error(await r.text());
      setContent(bodyContent);
      setGuidedValues(parseGuidedValues(bodyContent, fields));
      setMsg("Saved. If you edited the scanner daemon, use Restart daemon on the Dashboard.");
    } catch (e) {
      setMsg(String(e));
    } finally {
      setLoading(false);
    }
  };

  const resetToDefaults = async () => {
    if (
      !window.confirm(
        "Reset clamd.conf and freshclam.conf to the app's built-in starter templates? Timestamped .bak copies are created like a normal save. Paths in the templates are Linux-style -- adjust them for your OS (see Instructions).",
      )
    ) {
      return;
    }
    setLoading(true);
    setMsg(null);
    try {
      const r = await api("/api/config/reset", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ which: "both" }),
      });
      if (!r.ok) throw new Error(await r.text());
      await load();
      setEditorMode("raw");
      setMsg("Reset complete. Review paths in Raw mode, then restart the daemon from the Dashboard.");
    } catch (e) {
      setMsg(String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card">
      <p className="section-label">Configuration</p>
      <h2>ClamAV settings</h2>
      <p className="hint" style={{ marginBottom: "1rem" }}>
        Use <strong>Guided</strong> for common options with short explanations, or <strong>Raw</strong> for the
        full file. Each save writes a timestamped <code>.bak</code>. Lines not covered by Guided stay as-is
        until you edit them in Raw.
      </p>

      <div className="segmented" role="tablist" aria-label="Config file">
        <button
          type="button"
          role="tab"
          aria-selected={which === "clamd"}
          className={which === "clamd" ? "active" : ""}
          onClick={() => setWhich("clamd")}
        >
          clamd.conf
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={which === "freshclam"}
          className={which === "freshclam" ? "active" : ""}
          onClick={() => setWhich("freshclam")}
        >
          freshclam.conf
        </button>
      </div>

      <div className="segmented" role="tablist" aria-label="Editor mode" style={{ marginTop: "0.75rem" }}>
        <button
          type="button"
          role="tab"
          aria-selected={editorMode === "guided"}
          className={editorMode === "guided" ? "active" : ""}
          onClick={switchToGuided}
        >
          Guided
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={editorMode === "raw"}
          className={editorMode === "raw" ? "active" : ""}
          onClick={switchToRaw}
        >
          Raw file
        </button>
      </div>

      <div className="row" style={{ margin: "1rem 0" }}>
        <button type="button" className="btn btn-ghost" onClick={load} disabled={loading}>
          {loading ? (
            <>
              <span className="spinner-inline" aria-hidden />
              Loading…
            </>
          ) : (
            "Reload from disk"
          )}
        </button>
        <button type="button" className="btn btn-primary" onClick={save} disabled={loading}>
          Save changes
        </button>
        {editorMode === "raw" && (
          <button type="button" className="btn btn-danger" onClick={resetToDefaults} disabled={loading}>
            Reset files to default
          </button>
        )}
      </div>

      {editorMode === "guided" ? (
        <>
          <p className="guided-footnote">
            Showing frequently edited directives. Other settings remain in the file and appear in Raw mode.
          </p>
          <div className="guided-stack">
            {fields.map((f) => (
              <div key={f.key} className="guided-field">
                <label htmlFor={`g-${f.key}`}>{f.label}</label>
                <p className="field-hint-text">{f.hint}</p>
                <input
                  id={`g-${f.key}`}
                  type="text"
                  value={guidedValues[f.key] ?? ""}
                  onChange={(e) => setGuidedValues((prev) => ({ ...prev, [f.key]: e.target.value }))}
                  placeholder={`${f.key} …`}
                  spellCheck={false}
                />
              </div>
            ))}
          </div>
        </>
      ) : (
        <>
          <label htmlFor="cfg">Full file (exactly as on disk after merge)</label>
          <textarea id="cfg" value={content} onChange={(e) => setContent(e.target.value)} spellCheck={false} />
        </>
      )}
      {msg && <p className="hint">{msg}</p>}
    </div>
  );
}

type ScanMode = "quick" | "full" | "custom";

type ScanLine = {
  file: string | null;
  status: "ok" | "found" | "skip" | "info";
  detail: string | null;
};

type ScanStreamState = {
  type?: string;
  status: string;
  mode?: string;
  targetLabel?: string;
  targetPath?: string;
  filesScanned: number;
  totalFiles: number | null;
  countPartial: boolean;
  progress: number;
  progressExact: boolean;
  currentFile: string;
  infectedCount: number;
  scanLines?: ScanLine[];
  stdoutTail?: string;
  exitCode?: number | null;
  exitSignal?: string | null;
  spawnError?: string | null;
  findings?: string[];
};

type ScanHistoryEntry = {
  id: string;
  endedAt: number;
  mode: string;
  targetLabel: string;
  status: string;
  infectedCount: number;
};

function ScanLogViewer({ lines, running }: { lines: ScanLine[]; running: boolean }) {
  const logRef = useRef<HTMLDivElement>(null);
  const autoScrollRef = useRef(true);

  useEffect(() => {
    const el = logRef.current;
    if (!el || !autoScrollRef.current) return;
    el.scrollTop = el.scrollHeight;
  }, [lines]);

  const handleScroll = () => {
    const el = logRef.current;
    if (!el) return;
    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 48;
    autoScrollRef.current = nearBottom;
  };

  if (lines.length === 0 && !running) return null;

  return (
    <div className="scan-log-viewer" ref={logRef} onScroll={handleScroll}>
      {lines.length === 0 && running && (
        <div className="scan-log-line scan-log-info">Waiting for scanner output...</div>
      )}
      {lines.map((l, i) => {
        if (l.status === "info") {
          return (
            <div key={i} className="scan-log-line scan-log-info">
              {l.detail}
            </div>
          );
        }
        const cls =
          l.status === "found"
            ? "scan-log-found"
            : l.status === "skip"
              ? "scan-log-skip"
              : "scan-log-ok";
        const tag =
          l.status === "found" ? "THREAT" : l.status === "skip" ? "ERROR" : "OK";
        return (
          <div key={i} className={`scan-log-line ${cls}`}>
            <span className="scan-log-tag">{tag}</span>
            <span className="scan-log-path">{l.file}</span>
            {l.status === "found" && l.detail && (
              <span className="scan-log-detail">{l.detail}</span>
            )}
          </div>
        );
      })}
      {running && <div className="scan-log-cursor" />}
    </div>
  );
}

function ScanPanel({
  health,
  session,
  setSession,
  onRefresh: _onRefresh,
}: {
  health: Health | null;
  session: ScanSessionState;
  setSession: React.Dispatch<React.SetStateAction<ScanSessionState>>;
  onRefresh: (silent?: boolean) => void | Promise<void>;
}) {
  const [mode, setMode] = useState<ScanMode>("quick");
  const [customPath, setCustomPath] = useState(".");
  const [history, setHistory] = useState<ScanHistoryEntry[]>([]);
  const esRef = useRef<EventSource | null>(null);
  const streamDoneRef = useRef(false);

  const { activeScanId, live, scanErr, pendingStart } = session;
  const setActiveScanId = (id: string | null) => setSession((s) => ({ ...s, activeScanId: id }));
  const setLive = (l: ScanStreamState | null) => setSession((s) => ({ ...s, live: l }));
  const setScanErr = (e: string | null) => setSession((s) => ({ ...s, scanErr: e }));
  const setPendingStart = (b: boolean) => setSession((s) => ({ ...s, pendingStart: b }));

  const scanMeta = health?.scan;

  const running =
    pendingStart ||
    !!(live && ["queued", "preparing", "running"].includes(live.status));

  const finished = !running && live && ["completed", "cancelled", "error"].includes(live.status);

  const loadHistory = useCallback(async () => {
    try {
      const r = await api("/api/scan/history");
      if (!r.ok) return;
      const j = (await r.json()) as { items?: ScanHistoryEntry[] };
      setHistory((j.items || []).slice(0, 8));
    } catch {
      /* ignore */
    }
  }, []);

  useEffect(() => {
    void loadHistory();
  }, [loadHistory]);

  useEffect(() => {
    if (!activeScanId) return;
    streamDoneRef.current = false;
    const es = new EventSource(`/api/scan/stream?id=${encodeURIComponent(activeScanId)}`);
    esRef.current = es;
    es.onmessage = (ev) => {
      try {
        const m = JSON.parse(ev.data) as ScanStreamState & { type: string; findings?: string[] };
        setPendingStart(false);
        if (m.type === "state") {
          setLive(m);
        } else if (m.type === "done") {
          streamDoneRef.current = true;
          setLive(m);
          es.close();
          esRef.current = null;
          setActiveScanId(null);
          void loadHistory();
        }
      } catch {
        setScanErr("Invalid scan stream data");
      }
    };
    es.onerror = () => {
      setPendingStart(false);
      es.close();
      esRef.current = null;
      setActiveScanId(null);
      if (!streamDoneRef.current) {
        setScanErr(scanErr || "Scan stream disconnected");
      }
    };
    return () => {
      es.close();
      if (esRef.current === es) esRef.current = null;
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeScanId]);

  const startScan = async () => {
    setScanErr(null);
    streamDoneRef.current = false;
    setPendingStart(true);
    setLive(null);
    esRef.current?.close();
    setActiveScanId(null);
    try {
      const r = await api("/api/scan/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          mode,
          path: mode === "custom" ? customPath : undefined,
        }),
      });
      const j = (await r.json()) as { scanId?: string; error?: string };
      if (!r.ok) throw new Error(j.error || "Scan request failed");
      if (!j.scanId) throw new Error("No scan id returned");
      setActiveScanId(j.scanId);
    } catch (e: unknown) {
      setPendingStart(false);
      setScanErr(e instanceof Error ? e.message : String(e));
    }
  };

  const cancelScan = async () => {
    if (!activeScanId) return;
    try {
      await api("/api/scan/cancel", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: activeScanId }),
      });
    } catch (e: unknown) {
      setScanErr(e instanceof Error ? e.message : String(e));
    }
  };

  const progress = live?.progress ?? 0;
  const indeterminate = running && live && !live.progressExact && live.status !== "preparing";
  const showProgress = running || !!finished;
  const scanLines = live?.scanLines ?? [];

  const summaryStatusCls =
    live?.status === "completed" && live.infectedCount === 0
      ? "scan-summary-clean"
      : live?.status === "completed" && live.infectedCount > 0
        ? "scan-summary-threats"
        : live?.status === "error"
          ? "scan-summary-error"
          : "";

  return (
    <div className="card">
      <p className="section-label">Scan</p>
      <h2>Virus scan</h2>

      {!running && !finished && (
        <>
          <div className="scan-mode-grid">
            <button
              type="button"
              className={`scan-mode-card ${mode === "quick" ? "selected" : ""}`}
              onClick={() => setMode("quick")}
            >
              <strong>Standard scan</strong>
              <span>Downloads, Documents, Desktop, …</span>
            </button>
            <button
              type="button"
              className={`scan-mode-card ${mode === "full" ? "selected" : ""}`}
              onClick={() => setMode("full")}
            >
              <strong>Full system</strong>
              <span>{scanMeta?.fullPath ?? "/"}</span>
            </button>
            <button
              type="button"
              className={`scan-mode-card ${mode === "custom" ? "selected" : ""}`}
              onClick={() => setMode("custom")}
            >
              <strong>Custom path</strong>
              <span>Choose a folder</span>
            </button>
          </div>

          {mode === "quick" && scanMeta?.quickDirs && (
            <p className="hint" style={{ marginBottom: "0.65rem", fontSize: "0.8rem" }}>
              Scans: {scanMeta.quickDirs.map((d) => d.split("/").pop()).join(", ")}
            </p>
          )}

          {mode === "custom" && (
            <div style={{ marginBottom: "1rem" }}>
              <label htmlFor="scanpath">Path</label>
              <input
                id="scanpath"
                type="text"
                value={customPath}
                onChange={(e) => setCustomPath(e.target.value)}
                placeholder="/Users/you/Documents or relative path"
              />
            </div>
          )}

          {mode === "full" && (
            <div className="warning-banner" role="status" style={{ marginBottom: "1rem" }}>
              Full system scan reads the entire disk. This is slow and may hit permission errors.
            </div>
          )}
        </>
      )}

      {scanErr && (
        <div className="warning-banner" role="alert" style={{ borderColor: "rgba(224,93,93,0.45)", background: "rgba(224,93,93,0.1)", color: "#ffb4b4", marginBottom: "1rem" }}>
          {scanErr}
        </div>
      )}

      <div className="action-grid" style={{ marginBottom: "1rem" }}>
        {!running && !finished && (
          <button type="button" className="btn btn-primary" onClick={startScan} disabled={pendingStart}>
            {pendingStart ? (
              <>
                <span className="spinner-inline" aria-hidden />
                Starting…
              </>
            ) : (
              `▶ ${mode === "quick" ? "Standard" : mode === "full" ? "Full system" : "Custom"} scan`
            )}
          </button>
        )}
        {running && (
          <button type="button" className="btn btn-danger" onClick={cancelScan} disabled={!activeScanId}>
            Cancel scan
          </button>
        )}
        {finished && (
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => setSession(EMPTY_SCAN_SESSION)}
          >
            New scan
          </button>
        )}
      </div>

      {showProgress && (
        <div className="scan-progress-wrap">
          <div className="scan-progress-meta">
            <span>
              <strong>{progress}%</strong>
            </span>
            <span>
              {live?.progressExact && live.totalFiles != null
                ? `${live.filesScanned.toLocaleString()} / ${live.totalFiles.toLocaleString()} files`
                : `${(live?.filesScanned ?? 0).toLocaleString()} files scanned`}
              {(live?.infectedCount ?? 0) > 0 && (
                <> · <span style={{ color: "var(--danger)", fontWeight: 600 }}>{live!.infectedCount} threat{live!.infectedCount !== 1 ? "s" : ""}</span></>
              )}
            </span>
          </div>
          <div className="scan-progress-track">
            <div
              className={`scan-progress-fill ${indeterminate ? "indeterminate" : ""}`}
              style={indeterminate ? undefined : { width: `${Math.max(2, progress)}%` }}
            />
          </div>
        </div>
      )}

      {finished && live && (
        <div className={`scan-summary-banner ${summaryStatusCls}`}>
          {live.status === "completed" && live.infectedCount === 0 && (
            <>No threats found. {live.filesScanned.toLocaleString()} files scanned.</>
          )}
          {live.status === "completed" && live.infectedCount > 0 && (
            <>{live.infectedCount} threat{live.infectedCount !== 1 ? "s" : ""} found and quarantined. {live.filesScanned.toLocaleString()} files scanned. Check the Quarantine tab to review.</>
          )}
          {live.status === "error" && (
            <>{live.spawnError || `Scan failed (exit code ${live.exitCode}).`}</>
          )}
          {live.status === "cancelled" && <>Scan cancelled.</>}
        </div>
      )}

      <ScanLogViewer lines={scanLines} running={running} />

      {live?.findings && live.findings.length > 0 && !running && (
        <details className="advanced" style={{ marginTop: "0.75rem" }} open>
          <summary>Threat details ({live.findings.length})</summary>
          <pre className="log-box" style={{ maxHeight: 200 }}>
            {live.findings.join("\n")}
          </pre>
        </details>
      )}

      {history.length > 0 && !running && (
        <>
          <p className="section-label" style={{ marginTop: "1.25rem" }}>
            Recent scans
          </p>
          <ul className="history-list">
            {history.map((h) => (
              <li key={`${h.id}-${h.endedAt}`} className="history-item">
                <div className="history-meta">
                  {new Date(h.endedAt).toLocaleString()} · {h.mode} · {h.targetLabel} ·{" "}
                  <strong>{h.status}</strong>
                  {h.infectedCount > 0 && (
                    <span style={{ color: "var(--danger)" }}> · {h.infectedCount} infected</span>
                  )}
                </div>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}

async function fetchInstallStatus(): Promise<InstallStatus | null> {
  try {
    const r = await api("/api/install/status");
    if (!r.ok) return null;
    return (await r.json()) as InstallStatus;
  } catch {
    return null;
  }
}

function autoInstallAvailabilityNote(st: InstallStatus): string {
  if (st.canAutomate) {
    return "";
  }
  if (st.platform === "darwin") {
    return "Automatic install is only available when Homebrew is available (for example /opt/homebrew/bin/brew or /usr/local/bin/brew, or brew on your PATH). Install Homebrew if needed, restart this app, and open this tab again. Until then, use the manual commands below.";
  }
  if (st.platform === "linux") {
    return "Automatic install is not available on Linux in this app. Install ClamAV with your distribution’s package manager using the terminal commands below (you may need sudo).";
  }
  if (st.platform === "win32") {
    return "Automatic install is not available on Windows in this app. Download the official ClamAV build for Windows from https://www.clamav.net/downloads , run the installer, then restart this app.";
  }
  return "Automatic install is not available on this operating system. Install ClamAV using vendor documentation, then use the Dashboard to confirm status.";
}

function AutoInstallPanel({
  health,
  onRefreshAll,
}: {
  health: Health | null;
  onRefreshAll: (silent?: boolean) => void | Promise<void>;
}) {
  const [st, setSt] = useState<InstallStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [log, setLog] = useState("");
  const [cmdLogs, setCmdLogs] = useState<TerminalLogEntry[]>([]);
  const [uninstallBusy, setUninstallBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    const j = await fetchInstallStatus();
    setSt(j);
    setLoading(false);
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const runStep = async (step: string, label: string) => {
    setBusy(label);
    setLog("");
    setCmdLogs([]);
    try {
      const r = await api("/api/install/step", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ step }),
      });
      const j = (await r.json()) as { terminalLogs?: TerminalLogEntry[]; message?: string; error?: string };
      const tl = Array.isArray(j.terminalLogs) ? j.terminalLogs : [];
      setCmdLogs(tl);
      setLog(tl.length ? "" : JSON.stringify(j, null, 2));
      await load();
      void onRefreshAll(true);
    } catch (e) {
      setLog(String(e));
    } finally {
      setBusy(null);
    }
  };

  const runFreshclam = async () => {
    setBusy("Updating definitions…");
    setLog("");
    setCmdLogs([]);
    try {
      const r = await api("/api/actions/freshclam", { method: "POST" });
      const j = (await r.json()) as { terminalLogs?: TerminalLogEntry[]; ok?: boolean; code?: number };
      const tl = Array.isArray(j.terminalLogs) ? j.terminalLogs : [];
      setCmdLogs(tl);
      setLog(tl.length ? `freshclam finished (code ${j.code ?? "?"})` : JSON.stringify(j, null, 2));
      await load();
      void onRefreshAll(true);
    } catch (e) {
      setLog(String(e));
    } finally {
      setBusy(null);
    }
  };

  const copyCmd = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCmdLogs([]);
      setLog("Copied to clipboard.");
    } catch {
      setCmdLogs([]);
      setLog("Could not copy — select the command and copy manually.");
    }
  };

  const runUninstall = async () => {
    const msg =
      st?.platform === "linux"
        ? "Uninstall ClamAV using pkexec (you will be prompted for your password). Continue?"
        : "Stop the service, remove the Homebrew formula, and clean up ClamAV files. Continue?";
    if (!window.confirm(msg)) return;
    setUninstallBusy(true);
    setLog("");
    setCmdLogs([]);
    try {
      const r = await api("/api/install/uninstall", { method: "POST" });
      const j = (await r.json()) as { terminalLogs?: TerminalLogEntry[]; ok?: boolean; message?: string };
      const tl = Array.isArray(j.terminalLogs) ? j.terminalLogs : [];
      setCmdLogs(tl);
      setLog(tl.length ? j.message || `Uninstall finished (ok=${String(j.ok)})` : JSON.stringify(j, null, 2));
      await load();
      void onRefreshAll(true);
    } catch (e) {
      setLog(String(e));
    } finally {
      setUninstallBusy(false);
    }
  };

  if (loading || !st) {
    return (
      <div className="card">
        <p className="section-label">Setup</p>
        <h2>Auto-install</h2>
        <p className="hint">{loading ? "Checking your system…" : "Could not load install status."}</p>
        {!loading && (
          <button type="button" className="btn btn-ghost" onClick={load}>
            Retry
          </button>
        )}
      </div>
    );
  }

  const ready =
    st.brew.clamavInstalled &&
    st.paths.listenerConfigured &&
    health?.clamav.daemonResponding &&
    st.binaries.clamdscanOk;

  const availabilityNote = autoInstallAvailabilityNote(st);
  const un = st.uninstall ?? { canAutomated: false, manualSteps: [] as { title: string; command: string }[] };
  const showAutomatedUninstall =
    un.canAutomated &&
    (st.platform === "linux" || (st.platform === "darwin" && st.brew.clamavInstalled));

  return (
    <div className="card">
      <p className="section-label">Setup</p>
      <h2>Auto-install</h2>
      <p className="hint" style={{ marginBottom: "0.75rem" }}>
        Guided install and daemon setup. On <strong>macOS with Homebrew</strong>, you can run the steps below
        from this app. On other systems, this tab explains what is not automated and shows commands to run
        yourself.
      </p>

      {availabilityNote && (
        <div
          className="card"
          style={{
            marginBottom: "1rem",
            borderColor: "var(--warn)",
            background: "var(--surface2)",
            padding: "0.85rem 1rem",
          }}
        >
          <p style={{ margin: 0, fontSize: "0.9rem" }}>
            <strong>Not available here:</strong> {availabilityNote}
          </p>
        </div>
      )}

      <div className="row" style={{ marginBottom: "1rem", flexWrap: "wrap", gap: "0.5rem" }}>
        {st.platform === "darwin" && (
          <span className={`status-pill ${st.brew.clamavInstalled ? "ok" : "bad"}`}>
            {st.brew.clamavInstalled ? "●" : "○"} Homebrew formula
          </span>
        )}
        <span className={`status-pill ${st.paths.listenerConfigured ? "ok" : "bad"}`}>
          {st.paths.listenerConfigured ? "●" : "○"} Daemon config (socket)
        </span>
        <span className={`status-pill ${st.binaries.freshclamOk ? "ok" : "bad"}`}>
          {st.binaries.freshclamOk ? "●" : "○"} freshclam on PATH
        </span>
        <span className={`status-pill ${st.binaries.clamdscanOk ? "ok" : "bad"}`}>
          {st.binaries.clamdscanOk ? "●" : "○"} clamdscan on PATH
        </span>
        <span className={`status-pill ${health?.clamav.daemonResponding ? "ok" : "wait"}`}>
          {health?.clamav.daemonResponding ? "●" : "○"} Daemon responding
        </span>
      </div>

      {ready && (
        <p className="hint" style={{ color: "var(--accent)", marginBottom: "1rem" }}>
          ClamAV looks ready. Open the <strong>Dashboard</strong> tab and use <strong>Refresh status</strong> if
          something still looks wrong.
        </p>
      )}

      {st.canAutomate && (
        <div className="row" style={{ marginBottom: "1rem", flexWrap: "wrap" }}>
          <button
            type="button"
            className="btn btn-primary"
            disabled={!!busy || st.brew.clamavInstalled}
            onClick={() => runStep("brew-install", "Installing ClamAV (Homebrew)…")}
          >
            {st.brew.clamavInstalled ? "ClamAV installed" : "Install ClamAV (brew)"}
          </button>
          <button
            type="button"
            className="btn btn-ghost"
            disabled={!!busy || !st.brew.clamavInstalled}
            onClick={() => runStep("ensure-config", "Configuring daemon…")}
          >
            Configure daemon (folders + socket)
          </button>
          <button type="button" className="btn btn-ghost" disabled={!!busy || !st.brew.clamavInstalled} onClick={runFreshclam}>
            Download virus definitions
          </button>
          <button
            type="button"
            className="btn btn-ghost"
            disabled={!!busy || !st.brew.clamavInstalled}
            onClick={() => runStep("start-service", "Starting service…")}
          >
            Start daemon (brew services)
          </button>
          <button
            type="button"
            className="btn btn-ghost"
            disabled={!!busy || !st.brew.clamavInstalled}
            onClick={() => runStep("fix-brew-permissions", "Fixing Homebrew ClamAV file ownership…")}
            title="If a previous admin retry took root ownership of Cellar paths, this restores them to your user."
          >
            Fix brew permissions
          </button>
        </div>
      )}

      {!st.canAutomate && st.manualSteps.length > 0 && (
        <>
          <h3 style={{ fontSize: "0.95rem", marginBottom: "0.5rem" }}>Install commands (run in Terminal)</h3>
          <ul className="hint" style={{ paddingLeft: "1.1rem", marginBottom: "1rem" }}>
            {st.manualSteps.map((m) => (
              <li key={m.title} style={{ marginBottom: "0.75rem" }}>
                <strong>{m.title}</strong>
                <div style={{ display: "flex", gap: "0.5rem", alignItems: "flex-start", marginTop: "0.35rem" }}>
                  <pre className="log-box" style={{ flex: 1, margin: 0, fontSize: "0.8rem", whiteSpace: "pre-wrap" }}>
                    {m.command}
                  </pre>
                  <button type="button" className="btn btn-ghost" style={{ flexShrink: 0 }} onClick={() => copyCmd(m.command)}>
                    Copy
                  </button>
                </div>
              </li>
            ))}
          </ul>
        </>
      )}

      {st.canAutomate && st.brew.path && (
        <p className="hint" style={{ fontSize: "0.8rem", marginBottom: "0.5rem" }}>
          Homebrew: <code>{st.brew.path}</code>
          {st.brew.version ? ` · ${st.brew.version}` : ""}
          <br />
          Config file: <code>{st.paths.clamdConf}</code>
        </p>
      )}

      <p className="section-label" style={{ marginTop: "1.25rem" }}>
        Uninstall
      </p>
      <p className="hint" style={{ marginBottom: "0.65rem" }}>
        Removes ClamAV where supported. <code>brew</code> runs as your user first; a permission error on macOS
        triggers one administrator retry. Linux tries package removal as your user, then <code>pkexec</code> if
        needed. Do not use <code>sudo brew</code> by default in Terminal.
      </p>
      {showAutomatedUninstall && (
        <div className="row" style={{ marginBottom: "0.85rem" }}>
          <button
            type="button"
            className="btn btn-danger"
            disabled={!!busy || uninstallBusy}
            onClick={() => void runUninstall()}
          >
            {uninstallBusy ? "Uninstalling…" : "Uninstall ClamAV (automated)"}
          </button>
        </div>
      )}
      {un.manualSteps.length > 0 && (
        <>
          <h3 style={{ fontSize: "0.95rem", marginBottom: "0.5rem" }}>
            {showAutomatedUninstall ? "Or uninstall manually" : "Uninstall commands"}
          </h3>
          <ul className="hint" style={{ paddingLeft: "1.1rem", marginBottom: "1rem" }}>
            {un.manualSteps.map((m) => (
              <li key={m.title} style={{ marginBottom: "0.75rem" }}>
                <strong>{m.title}</strong>
                <div style={{ display: "flex", gap: "0.5rem", alignItems: "flex-start", marginTop: "0.35rem" }}>
                  <pre className="log-box" style={{ flex: 1, margin: 0, fontSize: "0.8rem", whiteSpace: "pre-wrap" }}>
                    {m.command}
                  </pre>
                  <button type="button" className="btn btn-ghost" style={{ flexShrink: 0 }} onClick={() => copyCmd(m.command)}>
                    Copy
                  </button>
                </div>
              </li>
            ))}
          </ul>
        </>
      )}

      {busy && <p className="hint">{busy}</p>}
      <TerminalOutputPanel logs={cmdLogs} />
      {log && <pre className="log-box">{log}</pre>}

      <div className="row" style={{ marginTop: "0.75rem" }}>
        <button type="button" className="btn btn-ghost" onClick={load} disabled={!!busy || uninstallBusy}>
          Refresh setup checks
        </button>
      </div>
    </div>
  );
}

function InstructionsPanel() {
  return (
    <div className="card">
      <p className="section-label">Help</p>
      <h2>Instructions</h2>
      <p className="hint" style={{ marginBottom: "1rem" }}>
        This app talks to ClamAV tools already installed on your computer. It does not replace a full security
        suite; it helps you run <strong>clamd</strong>, <strong>freshclam</strong>, and scans from one place.
      </p>

      <h2 style={{ fontSize: "0.95rem", marginTop: "1.25rem" }}>Official downloads & docs</h2>
      <ul className="instructions-links">
        <li>
          <a href="https://www.clamav.net/downloads" target="_blank" rel="noreferrer">
            ClamAV downloads
          </a>{" "}
          — installers and source
        </li>
        <li>
          <a href="https://docs.clamav.net/" target="_blank" rel="noreferrer">
            ClamAV documentation
          </a>{" "}
          — install, configure, clamonacc
        </li>
      </ul>

      <h2 style={{ fontSize: "0.95rem", marginTop: "1.25rem" }}>Install by operating system</h2>
      <div className="instructions-os">
        <section>
          <h3>macOS</h3>
          <p>
            Use the <strong>Auto-install</strong> tab for guided Homebrew steps when available. Or install with{" "}
            <a href="https://brew.sh" target="_blank" rel="noreferrer">
              Homebrew
            </a>
            : <code>brew install clamav</code>, then <code>brew services start clamav</code>. Config paths in{" "}
            <strong>Config</strong> should match Homebrew’s <code>/opt/homebrew/etc/clamav</code> or{" "}
            <code>/usr/local/etc/clamav</code>.
          </p>
        </section>
        <section>
          <h3>Windows</h3>
          <p>
            Use the official ClamAV Windows installer from the downloads page. After install, open this app’s{" "}
            <strong>Dashboard</strong> to confirm <strong>freshclam</strong> and <strong>clamdscan</strong> show
            as installed. Use <strong>Start daemon</strong> if the service is stopped (may need Administrator).
            Schedules use <strong>Task Scheduler</strong> on Windows.
          </p>
        </section>
        <section>
          <h3>Linux</h3>
          <p>
            Install with your package manager (e.g. <code>apt install clamav clamav-daemon</code> on Debian/Ubuntu).
            Enable <code>clamav-daemon</code> with systemd. Optional on-access scanning uses{" "}
            <code>clamonacc</code> — if your distro ships it, the Dashboard may show <strong>Real-time protection</strong>{" "}
            controls.
          </p>
        </section>
      </div>

      <h2 style={{ fontSize: "0.95rem", marginTop: "1.25rem" }}>Using this app</h2>
      <ol className="instructions-steps">
        <li>
          <strong>Auto-install</strong> — On Mac with Homebrew, install ClamAV, apply daemon socket config, fetch
          definitions, and start the service from one place; uninstall is on the same tab. Linux can uninstall via{" "}
          <code>pkexec</code> (password). Never use <code>sudo brew</code>.
        </li>
        <li>
          <strong>Dashboard</strong> — Check tools, firewall summary, start/stop the scanner daemon (Linux:{" "}
          <code>pkexec</code> password; Windows: UAC; macOS Homebrew: no <code>sudo brew</code>), download
          definitions (progress bar), and see your scan folder path.
        </li>
        <li>
          <strong>Scan</strong> — Pick quick, full, or custom path; watch the progress bar and current file; cancel
          if needed. Recent runs are listed from saved history.
        </li>
        <li>
          <strong>Schedules</strong> — On macOS/Linux, add cron jobs for freshclam or clamdscan.
        </li>
        <li>
          <strong>Config</strong> — Guided fields or full raw files; in Raw mode you can <strong>Reset files to default</strong>{" "}
          (starter templates — edit paths afterward).
        </li>
      </ol>
    </div>
  );
}

function shQuote(p: string) {
  return JSON.stringify(p);
}

function buildPresets(scanRoot: string) {
  const root = scanRoot || "";
  const base = root ? root.replace(/[/\\]+$/, "") : "";
  const freshLog = base ? `${base}/freshclam-cron.log` : "/path/to/your/scan/folder/freshclam-cron.log";
  const scanLog = base ? `${base}/scheduled-scan.log` : "/path/to/your/scan/folder/scheduled-scan.log";
  return [
    {
      title: "Nightly definition update",
      desc: "Every day at 2:15 AM",
      schedule: "15 2 * * *",
      command: `freshclam --foreground --stdout >> ${shQuote(freshLog)} 2>&1`,
      comment: "ClamAV Control: nightly definitions",
    },
    {
      title: "Weekly full folder scan",
      desc: "Sundays at 3:30 AM",
      schedule: "30 3 * * 0",
      command: `clamdscan --fdpass -v ${shQuote(root || "/path/to/your/scan/folder")} >> ${shQuote(scanLog)} 2>&1 || true`,
      comment: "ClamAV Control: weekly scan",
    },
  ];
}

type QuarantineItem = {
  name: string;
  path: string;
  size: number;
  quarantinedAt: number;
};

function formatBytes(b: number): string {
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / (1024 * 1024)).toFixed(1)} MB`;
}

function QuarantinePanel() {
  const [items, setItems] = useState<QuarantineItem[]>([]);
  const [dir, setDir] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await api("/api/quarantine");
      if (!r.ok) throw new Error(await r.text());
      const j = (await r.json()) as { dir: string; items: QuarantineItem[] };
      setItems(j.items || []);
      setDir(j.dir || "");
    } catch (e) {
      setMsg({ ok: false, text: String(e) });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const deleteItem = async (name: string) => {
    setBusy(name);
    setMsg(null);
    try {
      const r = await api("/api/quarantine/delete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name }),
      });
      const j = (await r.json()) as { ok?: boolean; error?: string };
      if (j.ok) {
        setMsg({ ok: true, text: `Deleted ${name}` });
        void load();
      } else {
        setMsg({ ok: false, text: j.error || "Delete failed" });
      }
    } catch (e) {
      setMsg({ ok: false, text: String(e) });
    } finally {
      setBusy(null);
    }
  };

  const restoreItem = async (name: string) => {
    setBusy(name);
    setMsg(null);
    try {
      const r = await api("/api/quarantine/restore", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name }),
      });
      const j = (await r.json()) as { ok?: boolean; error?: string; restoredTo?: string };
      if (j.ok) {
        setMsg({ ok: true, text: `Restored ${name} to ${j.restoredTo}` });
        void load();
      } else {
        setMsg({ ok: false, text: j.error || "Restore failed" });
      }
    } catch (e) {
      setMsg({ ok: false, text: String(e) });
    } finally {
      setBusy(null);
    }
  };

  const deleteAll = async () => {
    if (!confirm("Permanently delete all quarantined files? This cannot be undone.")) return;
    setBusy("__all__");
    setMsg(null);
    try {
      const r = await api("/api/quarantine/delete-all", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      const j = (await r.json()) as { ok?: boolean; deleted?: number; error?: string };
      if (j.ok) {
        setMsg({ ok: true, text: `Deleted ${j.deleted} file${j.deleted !== 1 ? "s" : ""}` });
        void load();
      } else {
        setMsg({ ok: false, text: j.error || "Delete all failed" });
      }
    } catch (e) {
      setMsg({ ok: false, text: String(e) });
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="card">
      <p className="section-label">Quarantine</p>
      <h2>Quarantined threats</h2>
      <p className="hint" style={{ marginBottom: "0.75rem" }}>
        When a scan finds malware, the infected file is automatically moved here.
        You can permanently delete it or restore it if you believe it is a false positive.
        {dir && (
          <>
            <br />
            Quarantine folder: <code>{dir}</code>
          </>
        )}
      </p>

      {msg && (
        <div
          className="svc-action-banner"
          role="status"
          style={{
            marginBottom: "0.85rem",
            padding: "0.6rem 0.85rem",
            borderRadius: 10,
            fontSize: "0.82rem",
            border: `1px solid ${msg.ok ? "rgba(61,217,160,0.45)" : "rgba(224,93,93,0.5)"}`,
            background: msg.ok ? "rgba(61,217,160,0.1)" : "rgba(224,93,93,0.1)",
            color: msg.ok ? "#9ff5d2" : "#ffb4b4",
          }}
        >
          {msg.ok ? "✓ " : "✕ "}{msg.text}
        </div>
      )}

      <div className="action-grid" style={{ marginBottom: "1rem" }}>
        <button type="button" className="btn btn-ghost" onClick={() => void load()} disabled={loading}>
          ⟳ Refresh
        </button>
        {items.length > 0 && (
          <button
            type="button"
            className="btn btn-danger"
            onClick={() => void deleteAll()}
            disabled={!!busy}
          >
            Delete all ({items.length})
          </button>
        )}
      </div>

      {loading && <p className="hint"><span className="spinner-inline" aria-hidden /> Loading…</p>}

      {!loading && items.length === 0 && (
        <div className="quarantine-empty">
          <p style={{ textAlign: "center", color: "var(--muted)", padding: "2rem 0" }}>
            No quarantined files. Threats found during scans will appear here.
          </p>
        </div>
      )}

      {!loading && items.length > 0 && (
        <div className="quarantine-list">
          {items.map((item) => (
            <div key={item.name} className="quarantine-item">
              <div className="quarantine-item-info">
                <span className="quarantine-item-name" title={item.path}>{item.name}</span>
                <span className="quarantine-item-meta">
                  {formatBytes(item.size)} · {new Date(item.quarantinedAt).toLocaleString()}
                </span>
              </div>
              <div className="quarantine-item-actions">
                <button
                  type="button"
                  className="btn btn-ghost btn-sm"
                  disabled={!!busy}
                  onClick={() => void restoreItem(item.name)}
                  title="Restore to Desktop (use only if false positive)"
                >
                  Restore
                </button>
                <button
                  type="button"
                  className="btn btn-danger btn-sm"
                  disabled={!!busy}
                  onClick={() => void deleteItem(item.name)}
                  title="Permanently delete this file"
                >
                  Delete
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function CronPanel() {
  const [jobs, setJobs] = useState<CronJob[]>([]);
  const [raw, setRaw] = useState("");
  const [schedule, setSchedule] = useState("0 3 * * *");
  const [command, setCommand] = useState("freshclam --foreground --stdout");
  const [comment, setComment] = useState("ClamAV Control job");
  const [msg, setMsg] = useState<string | null>(null);
  const [scanRoot, setScanRoot] = useState("");
  const [cronBlocked, setCronBlocked] = useState(false);

  const presets = buildPresets(scanRoot);

  const load = useCallback(async () => {
    setMsg(null);
    try {
      const h = await api("/api/health");
      if (h.ok) {
        const hj = (await h.json()) as Health;
        setScanRoot(hj.paths?.scanRoot || "");
      }
      const r = await api("/api/cron");
      if (r.status === 501) {
        setCronBlocked(true);
        setJobs([]);
        setRaw("");
        return;
      }
      setCronBlocked(false);
      if (!r.ok) throw new Error(await r.text());
      const j = await r.json();
      setJobs(j.jobs || []);
      setRaw(j.raw || "");
    } catch (e) {
      setMsg(String(e));
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const add = async () => {
    setMsg(null);
    try {
      const r = await api("/api/cron", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ schedule, command, comment }),
      });
      if (!r.ok) throw new Error(await r.text());
      await load();
      setMsg("Job added to your crontab.");
    } catch (e) {
      setMsg(String(e));
    }
  };

  const remove = async (id: number) => {
    setMsg(null);
    try {
      const r = await api(`/api/cron/${id}`, { method: "DELETE" });
      if (!r.ok) throw new Error(await r.text());
      await load();
      setMsg("Job removed.");
    } catch (e) {
      setMsg(String(e));
    }
  };

  if (cronBlocked) {
    return (
      <div className="card">
        <p className="section-label">Schedules</p>
        <h2>Windows — use Task Scheduler</h2>
        <p className="hint">
          This app does not edit cron on Windows. Open <strong>Task Scheduler</strong> and create tasks that run{" "}
          <code>freshclam</code> or <code>clamdscan</code> on a schedule. Use the Dashboard for one-off updates
          and scans.
        </p>
      </div>
    );
  }

  return (
    <div className="card">
      <p className="section-label">Automation</p>
      <h2>Timer scans (crontab)</h2>

      <div className={`schedule-status-banner ${jobs.length > 0 ? "has-jobs" : ""}`}>
        <div>
          <div className="count" aria-live="polite">
            {jobs.length}
          </div>
        </div>
        <div className="label">
          {jobs.length === 0
            ? "No timer scans are active in your user crontab. Add one below to schedule freshclam or clamdscan."
            : jobs.length === 1
              ? "One scheduled job is active (shown below)."
              : `${jobs.length} scheduled jobs are active (listed below).`}
        </div>
      </div>

      <p className="hint" style={{ marginBottom: "1rem" }}>
        Jobs run as <strong>you</strong> on this computer. Use five fields: minute, hour, day of month, month,
        day of week. You may need <code>sudo</code> inside the command on some setups. Presets fill in your
        current scan folder path.
      </p>

      <p className="section-label" style={{ marginTop: "0.5rem" }}>
        Quick presets
      </p>
      <div className="preset-grid">
        {presets.map((p) => (
          <button
            key={p.title}
            type="button"
            className="preset-btn"
            onClick={() => {
              setSchedule(p.schedule);
              setCommand(p.command);
              setComment(p.comment);
            }}
          >
            <strong>{p.title}</strong>
            <span style={{ color: "var(--muted)" }}>{p.desc}</span>
          </button>
        ))}
      </div>

      <label htmlFor="sched">When (cron schedule)</label>
      <input
        id="sched"
        type="text"
        value={schedule}
        onChange={(e) => setSchedule(e.target.value)}
        placeholder="0 3 * * *"
        style={{ marginBottom: "0.75rem" }}
      />
      <label htmlFor="cmd">Shell command</label>
      <input
        id="cmd"
        type="text"
        value={command}
        onChange={(e) => setCommand(e.target.value)}
        style={{ marginBottom: "0.75rem" }}
      />
      <label htmlFor="cmt">Note (comment above the job)</label>
      <input
        id="cmt"
        type="text"
        value={comment}
        onChange={(e) => setComment(e.target.value)}
        style={{ marginBottom: "1rem" }}
      />
      <div className="action-grid">
        <button type="button" className="btn btn-primary" onClick={add}>
          + Add to crontab
        </button>
        <button type="button" className="btn btn-ghost" onClick={load}>
          Refresh list
        </button>
      </div>

      {msg && <p className="hint">{msg}</p>}

      <p className="section-label" style={{ marginTop: "1.35rem" }}>
        Active timer scans
      </p>
      {jobs.length > 0 && (
        <div style={{ marginBottom: "1rem" }}>
          {jobs.map((j, index) => (
            <div key={j.id} className="timer-job-card">
              <div>
                <div className="job-meta">Job #{index + 1}</div>
                <div className="job-line">{j.line}</div>
              </div>
              <button type="button" className="btn btn-danger" onClick={() => remove(j.id)}>
                Remove
              </button>
            </div>
          ))}
        </div>
      )}

      <details className="advanced">
        <summary>Raw crontab text</summary>
        <pre className="log-box" style={{ maxHeight: 280 }}>
          {raw || "(empty)"}
        </pre>
      </details>
    </div>
  );
}
