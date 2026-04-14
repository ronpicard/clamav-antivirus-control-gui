import { useCallback, useEffect, useRef, useState } from "react";
import { applyGuidedValues, guideFieldsFor, parseGuidedValues, type GuideField } from "./clamavConfigGuide";

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
  dns?: {
    supported: boolean;
    ok: boolean;
    platform?: string;
    method?: string;
    service?: string | null;
    servers: string[];
    automatic?: boolean;
    matchedPreset?: string;
    displayLabel: string;
    detail?: string;
  };
  clamdService?: {
    running: boolean;
    unit: string | null;
    method: string;
    socketOk: boolean;
  };
  realtimeMonitor?: {
    running: boolean;
    method: string | null;
    watchedDirs: string[];
    filesScanned: number;
    threatsFound: number;
    lastEvent: RtEvent | null;
    startedAt: number | null;
    error: string | null;
  };
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

type RtEvent = {
  file: string | null;
  status: "clean" | "threat" | "error" | "scanning" | "info";
  detail: string | null;
  ts: number;
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

const TABS = [
  ["home", "Dashboard", "📊", "See what is working and refresh ClamAV"],
  ["realtime", "Real-time", "🛡️", "Monitor files in real time"],
  ["scan", "Scan", "🔎", "Scan files with live progress"],
  ["quarantine", "Quarantine", "🔒", "View and manage quarantined threats"],
  ["cron", "Schedules", "⏰", "Automate updates and scans (Mac/Linux)"],
  ["config", "Config", "⚙️", "Edit clamd and freshclam settings"],
  ["dns", "DNS", "🌐", "DNS resolver: OpenDNS, Google, Cloudflare, DHCP, custom"],
  ["settings", "Settings", "🔧", "App preferences"],
  ["instructions", "Instructions", "📖", "Install ClamAV and use this app"],
  ["auto-install", "Auto-install", "📦", "Install ClamAV — guided on Mac + Homebrew"],
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
  const [autoStartRealtime, setAutoStartRealtime] = useState(() => {
    try {
      return localStorage.getItem("clamav-autort-realtime") !== "0";
    } catch {
      return true;
    }
  });
  const [autoStartDaemon, setAutoStartDaemon] = useState(() => {
    try {
      return localStorage.getItem("clamav-autostart-daemon") === "1";
    } catch {
      return false;
    }
  });
  const [autoEnsureCronDefaults, setAutoEnsureCronDefaults] = useState(() => {
    try {
      return localStorage.getItem("clamav-autostart-cron") === "1";
    } catch {
      return false;
    }
  });
  const autoRtAttemptedRef = useRef(false);
  const autoDaemonAttemptedRef = useRef(false);
  const autoCronAttemptedRef = useRef(false);

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

  useEffect(() => {
    if (!autoStartRealtime) {
      autoRtAttemptedRef.current = false;
    }
  }, [autoStartRealtime]);

  useEffect(() => {
    if (err || !health || !autoStartRealtime) return;
    if (health.realtimeMonitor?.running) return;
    if (autoRtAttemptedRef.current) return;
    autoRtAttemptedRef.current = true;
    void (async () => {
      try {
        const r = await api("/api/realtime/start", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: "{}",
        });
        const j = (await r.json()) as { ok?: boolean };
        if (j.ok) {
          await refresh(true);
        } else {
          autoRtAttemptedRef.current = false;
        }
      } catch {
        autoRtAttemptedRef.current = false;
      }
    })();
  }, [health, err, autoStartRealtime, refresh]);

  useEffect(() => {
    if (!autoStartDaemon) {
      autoDaemonAttemptedRef.current = false;
    }
  }, [autoStartDaemon]);

  useEffect(() => {
    if (err || !health || !autoStartDaemon) return;
    if (health.clamav?.daemonResponding) return;
    if (autoDaemonAttemptedRef.current) return;
    autoDaemonAttemptedRef.current = true;
    void (async () => {
      try {
        const r = await api("/api/actions/clamd-service", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ action: "start" }),
        });
        const j = (await r.json()) as { ok?: boolean };
        if (j.ok) {
          await refresh(true);
        } else {
          autoDaemonAttemptedRef.current = false;
        }
      } catch {
        autoDaemonAttemptedRef.current = false;
      }
    })();
  }, [health, err, autoStartDaemon, refresh]);

  useEffect(() => {
    if (!autoEnsureCronDefaults) {
      autoCronAttemptedRef.current = false;
    }
  }, [autoEnsureCronDefaults]);

  useEffect(() => {
    if (err || !health || !autoEnsureCronDefaults) return;
    if (autoCronAttemptedRef.current) return;
    autoCronAttemptedRef.current = true;
    void (async () => {
      try {
        const r = await api("/api/cron/ensure-defaults", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: "{}",
        });
        const j = (await r.json()) as { ok?: boolean; skipped?: boolean };
        if (!r.ok || j.ok === false) {
          autoCronAttemptedRef.current = false;
        }
      } catch {
        autoCronAttemptedRef.current = false;
      }
    })();
  }, [health, err, autoEnsureCronDefaults]);

  return (
    <div className="app-shell">
        <header className="app-header">
          <div className="brand-row">
            <div className="brand-icon" aria-hidden>
              <img src="/icon.png" alt="" width={28} height={28} className="brand-icon-img" />
            </div>
            <div>
              <h1>ClamAV Control</h1>
              <p className="subtitle">Antivirus dashboard for your computer</p>
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

        {err && (
          <div className="card card-error" role="alert">
            <h2 style={{ color: "var(--danger)", marginBottom: "0.5rem" }}>Cannot reach the app</h2>
            <p style={{ margin: 0, color: "var(--muted)", fontSize: "0.9rem" }}>{err}</p>
            <button type="button" className="btn btn-primary" style={{ marginTop: "1rem" }} onClick={refresh}>
              Try again
            </button>
          </div>
        )}

        <div
          className={`panel-wrap panel-wrap-flex ${tab === "scan" ? "scan-panel-hidden" : ""}`}
          key={tab === "scan" ? "scan-persistent" : tab}
        >
          {tab === "home" && <Dashboard health={health} loading={loading} onRefresh={refresh} />}
          {tab === "realtime" && <RealtimePanel health={health} onRefresh={refresh} />}
          {tab === "auto-install" && <AutoInstallPanel health={health} onRefreshAll={refresh} />}
          {tab === "quarantine" && <QuarantinePanel />}
          {tab === "cron" && <CronPanel />}
          {tab === "config" && <ConfigPanel />}
          {tab === "dns" && <DnsPanel health={health} onRefresh={refresh} />}
          {tab === "settings" && (
            <SettingsPanel
              health={health}
              loading={loading}
              connectionErr={err}
              autoStartRealtime={autoStartRealtime}
              onAutoStartRealtimeChange={setAutoStartRealtime}
              autoStartDaemon={autoStartDaemon}
              onAutoStartDaemonChange={setAutoStartDaemon}
              autoEnsureCronDefaults={autoEnsureCronDefaults}
              onAutoEnsureCronDefaultsChange={setAutoEnsureCronDefaults}
              onRefresh={refresh}
            />
          )}
          {tab === "instructions" && <InstructionsPanel />}
        </div>
        <div className={`panel-wrap panel-wrap-flex ${tab === "scan" ? "" : "scan-panel-hidden"}`}>
          <ScanPanel health={health} session={scanSession} setSession={setScanSession} onRefresh={refresh} />
        </div>
    </div>
  );
}

function DashboardRealtimeControls({
  running,
  onRefresh,
  controlsDisabled,
}: {
  running: boolean;
  onRefresh: (silent?: boolean) => void | Promise<void>;
  controlsDisabled?: boolean;
}) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const block = !!(controlsDisabled || busy);

  const start = async () => {
    setBusy(true);
    setMsg(null);
    try {
      const r = await api("/api/realtime/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      const j = await r.json();
      if (j.ok) {
        setMsg({ ok: true, text: `Real-time started (${j.method})` });
        void onRefresh(true);
      } else {
        setMsg({ ok: false, text: j.error || "Failed to start" });
      }
    } catch (e) {
      setMsg({ ok: false, text: String(e) });
    } finally {
      setBusy(false);
    }
  };

  const stop = async () => {
    setBusy(true);
    setMsg(null);
    try {
      const r = await api("/api/realtime/stop", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      const j = await r.json();
      if (j.ok) {
        setMsg({ ok: true, text: "Real-time stopped" });
        void onRefresh(true);
      } else {
        setMsg({ ok: false, text: j.error || "Failed to stop" });
      }
    } catch (e) {
      setMsg({ ok: false, text: String(e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="dash-section">
      <p className="section-label">Real-time folder monitor</p>
      <p className="hint" style={{ margin: "0 0 0.65rem", fontSize: "0.82rem" }}>
        Same as the Real-time tab — watches key folders and scans new or changed files.
      </p>
      {msg && (
        <div
          className={`action-banner fade-in ${msg.ok ? "ok" : "err"}`}
          role="status"
          style={{ marginBottom: "0.65rem" }}
        >
          {msg.ok ? "✓ " : "✕ "}
          {msg.text}
        </div>
      )}
      <div className="action-grid">
        <button
          type="button"
          className="btn btn-primary"
          disabled={block || running}
          onClick={() => void start()}
        >
          {busy && !running ? (
            <>
              <span className="spinner-inline" aria-hidden />
              Starting…
            </>
          ) : (
            "Enable"
          )}
        </button>
        <button
          type="button"
          className="btn btn-ghost"
          disabled={block || !running}
          onClick={() => void stop()}
        >
          {busy && running ? (
            <>
              <span className="spinner-inline" aria-hidden />
              Stopping…
            </>
          ) : (
            "Disable"
          )}
        </button>
      </div>
    </div>
  );
}

function dnsDashboardLine(dns: Health["dns"] | undefined): { text: string; title: string } {
  if (!dns) return { text: "—", title: "" };
  const title = [dns.displayLabel, dns.service && `Interface: ${dns.service}`, dns.detail].filter(Boolean).join("\n");
  if (!dns.supported) return { text: "—", title: title || dns.detail || "" };
  if (dns.automatic || !(dns.servers && dns.servers.length)) return { text: "DHCP", title };
  return { text: dns.servers.join(", "), title };
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
          text: `Service command succeeded.`,
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

  const dns = health?.dns;
  const dnsPillOk = dns?.supported && dns.ok !== false;
  const dnsSummary = dnsDashboardLine(dns);

  return (
    <div className="card fade-in">
      <h2 style={{ marginBottom: "0.25rem" }}>Dashboard</h2>
      {loading && (
        <div style={{ padding: "2rem 0" }}>
          <p className="hint">
            <span className="spinner-inline" aria-hidden />
            Checking your system…
          </p>
          <div className="skeleton-block" aria-hidden />
        </div>
      )}
      {!loading && health && (
        <>
          <div className="status-grid">
            <span className={`status-pill ${c?.freshclamInstalled ? "ok" : "bad"}`}>
              <span className="dot" aria-hidden />
              Definitions
              <span className="status-pill-muted">freshclam</span>
            </span>
            <span className={`status-pill ${c?.clamdscanInstalled ? "ok" : "bad"}`}>
              <span className="dot" aria-hidden />
              Scanner
              <span className="status-pill-muted">clamdscan</span>
            </span>
            <span className={`status-pill ${daemonPillClass}`} title={daemonPillTitle || undefined}>
              <span className="dot" aria-hidden />
              Daemon
              <span className="status-pill-muted">{daemonResponding ? "online" : "offline"}</span>
            </span>
            <span className={`status-pill ${fwOk ? "ok" : fwOff ? "bad" : "wait"}`} title={fw?.detail}>
              <span className="dot" aria-hidden />
              Firewall
              <span className="status-pill-muted">
                {fwOk ? "on" : fwOff ? "off" : "unknown"}
              </span>
            </span>
            <span className={`status-pill ${health.realtimeMonitor?.running ? "ok" : "wait"}`}>
              <span className="dot" aria-hidden />
              Real-time
              <span className="status-pill-muted">{health.realtimeMonitor?.running ? "active" : "off"}</span>
            </span>
            <span
              className={`status-pill ${dnsPillOk ? "ok" : dns?.supported === false ? "bad" : "wait"}`}
              title={dnsSummary.title || undefined}
            >
              <span className="dot" aria-hidden />
              DNS
              <span className="status-pill-muted dns-pill-nums">{dnsSummary.text}</span>
            </span>
          </div>

          <DashboardRealtimeControls
            running={!!health.realtimeMonitor?.running}
            onRefresh={onRefresh}
            controlsDisabled={svcBusy || !!busy || defStreaming}
          />

          {svcBanner && (
            <div className={`action-banner fade-in ${svcBanner.ok ? "ok" : "err"}`} role="status">
              {svcBanner.ok ? "✓ " : "✕ "}{svcBanner.text}
            </div>
          )}

          {(svcBusy || busy) && (
            <p className="hint" style={{ margin: "0.5rem 0" }}>
              <span className="spinner-inline" aria-hidden />
              {svcBusy ? "Running command…" : busy}
            </p>
          )}

          <div className="dashboard-sections">
            <div className="dash-section">
              <p className="section-label">Firewall</p>
              <div className="action-grid">
                <button type="button" className="btn btn-primary" disabled={svcBusy || !!busy || fwOk} onClick={() => void firewallAction("on")}>
                  Enable
                </button>
                <button type="button" className="btn btn-ghost" disabled={svcBusy || !!busy || fwOff} onClick={() => void firewallAction("off")}>
                  Disable
                </button>
              </div>
            </div>

            <div className="dash-section">
              <p className="section-label">Scanner daemon</p>
              <div className="action-grid">
                <button type="button" className="btn btn-primary" disabled={svcBusy || !!busy} onClick={() => void clamdServiceAction("start")}>
                  Start
                </button>
                <button type="button" className="btn btn-ghost" disabled={svcBusy || !!busy} onClick={() => void clamdServiceAction("stop")}>
                  Stop
                </button>
                <button type="button" className="btn btn-ghost" disabled={svcBusy || !!busy} onClick={() => void clamdServiceAction("restart")}>
                  Restart
                </button>
              </div>
            </div>

            <div className="dash-section">
              <p className="section-label">Quick actions</p>
              <div className="action-grid">
                <button type="button" className="btn btn-primary" disabled={!!busy || defStreaming} onClick={() => void onRefresh(true)}>
                  ↻ Refresh
                </button>
                <button type="button" className="btn btn-ghost" disabled={!!busy || defStreaming} onClick={runFreshclam}>
                  ⬇ Update definitions
                </button>
                <button type="button" className="btn btn-ghost" disabled={!!busy || defStreaming} onClick={restartClamd}>
                  ⟳ Restart daemon
                </button>
              </div>
            </div>
          </div>

          {defStreaming && (
            <div className="scan-progress-wrap fade-in" style={{ marginTop: "1rem" }}>
              <div className="scan-progress-meta">
                <span><strong>{defProgress}%</strong></span>
                <span>Updating definitions…</span>
              </div>
              <div className="scan-progress-track">
                <div className="scan-progress-fill" style={{ width: `${defProgress}%` }} />
              </div>
            </div>
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

const CUSTOM_SENTINEL = "__custom__";
const EMPTY_SENTINEL = "__empty__";

function GuidedFieldInput({
  field,
  value,
  onChange,
}: {
  field: GuideField;
  value: string;
  onChange: (v: string) => void;
}) {
  const opts = field.options ?? [];
  const hasOptions = opts.length > 0;
  const isPreset = hasOptions && opts.includes(value);
  const isCustom = !isPreset && value !== "";
  const [customMode, setCustomMode] = useState(isCustom);

  useEffect(() => {
    if (value === "" || opts.includes(value)) {
      setCustomMode(false);
    } else if (value !== "") {
      setCustomMode(true);
    }
  }, [value, opts]);

  if (!hasOptions) {
    return (
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={`${field.key} …`}
        spellCheck={false}
      />
    );
  }

  const handleSelect = (v: string) => {
    if (v === CUSTOM_SENTINEL) {
      setCustomMode(true);
      return;
    }
    if (v === EMPTY_SENTINEL) {
      onChange("");
      setCustomMode(false);
      return;
    }
    onChange(v);
    setCustomMode(false);
  };

  const selectValue = customMode ? CUSTOM_SENTINEL : value === "" ? EMPTY_SENTINEL : value;

  return (
    <div className="guided-input-combo">
      <select
        value={selectValue}
        onChange={(e) => handleSelect(e.target.value)}
        className="guided-select"
      >
        <option value={EMPTY_SENTINEL}>— not set —</option>
        {opts.map((o) => (
          <option key={o} value={o}>
            {o}
          </option>
        ))}
        <option value={CUSTOM_SENTINEL}>Custom…</option>
      </select>
      {customMode && (
        <input
          type="text"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder="Enter custom value…"
          spellCheck={false}
          className="guided-custom-input"
          autoFocus
        />
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
      setMsg("Saved. Restart the daemon from the Dashboard to apply changes.");
    } catch (e) {
      setMsg(String(e));
    } finally {
      setLoading(false);
    }
  };

  const resetToDefaults = async () => {
    if (
      !window.confirm(
        "Reset both config files to defaults? .bak backups are created automatically.",
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
      setMsg("Reset complete. Review paths, then restart the daemon.");
    } catch (e) {
      setMsg(String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card fade-in">
      <h2 style={{ marginBottom: "0.25rem" }}>Configuration</h2>
      <p className="hint" style={{ marginBottom: "1rem" }}>
        Edit ClamAV settings. Each save creates a <code>.bak</code> backup.
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
                <label>{f.label}</label>
                <p className="field-hint-text">{f.hint}</p>
                <GuidedFieldInput
                  field={f}
                  value={guidedValues[f.key] ?? ""}
                  onChange={(v) => setGuidedValues((prev) => ({ ...prev, [f.key]: v }))}
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
  etaSeconds?: number | null;
  etaConfidence?: string;
  filesPerSecond?: number | null;
  currentFile: string;
  infectedCount: number;
  scanLines?: ScanLine[];
  stdoutTail?: string;
  exitCode?: number | null;
  exitSignal?: string | null;
  spawnError?: string | null;
  findings?: string[];
};

function formatScanEta(seconds: number | null | undefined): string {
  if (seconds == null || !Number.isFinite(seconds)) return "";
  const s = Math.round(seconds);
  if (s <= 0) return "";
  if (s < 120) return `~${s}s remaining`;
  const m = Math.floor(s / 60);
  const rs = s % 60;
  if (m < 120) return `~${m}m ${rs}s remaining`;
  const h = Math.floor(m / 60);
  const rm = m % 60;
  return `~${h}h ${rm}m remaining`;
}

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
  const etaText =
    running && live && live.status !== "preparing" && (live.etaSeconds ?? 0) > 0
      ? formatScanEta(live.etaSeconds)
      : "";
  const etaApprox = live?.etaConfidence === "estimate";
  const fpsText =
    live?.filesPerSecond != null && live.filesPerSecond > 0
      ? `${live.filesPerSecond.toLocaleString()} files/s`
      : "";

  const summaryStatusCls =
    live?.status === "completed" && live.infectedCount === 0
      ? "scan-summary-clean"
      : live?.status === "completed" && live.infectedCount > 0
        ? "scan-summary-threats"
        : live?.status === "error"
          ? "scan-summary-error"
          : "";

  return (
    <div className="card fade-in">
      <h2 style={{ marginBottom: "0.25rem" }}>Virus scan</h2>

      {!running && !finished && (
        <div className="fade-in">
          <div className="scan-mode-grid">
            <button
              type="button"
              className={`scan-mode-card ${mode === "quick" ? "selected" : ""}`}
              onClick={() => setMode("quick")}
            >
              <span className="scan-mode-icon">🔎</span>
              <strong>Standard</strong>
              <span className="scan-mode-hint">Common user folders</span>
            </button>
            <button
              type="button"
              className={`scan-mode-card ${mode === "full" ? "selected" : ""}`}
              onClick={() => setMode("full")}
            >
              <span className="scan-mode-icon">💽</span>
              <strong>Full system</strong>
              <span className="scan-mode-hint">Entire disk</span>
            </button>
            <button
              type="button"
              className={`scan-mode-card ${mode === "custom" ? "selected" : ""}`}
              onClick={() => setMode("custom")}
            >
              <span className="scan-mode-icon">📁</span>
              <strong>Custom</strong>
              <span className="scan-mode-hint">Pick a folder</span>
            </button>
          </div>

          {mode === "quick" && scanMeta?.quickDirs && (
            <p className="hint scan-dirs-hint">
              {scanMeta.quickDirs.map((d) => d.split("/").pop()).join(" · ")}
            </p>
          )}

          {mode === "custom" && (
            <div style={{ marginBottom: "1rem" }}>
              <input
                id="scanpath"
                type="text"
                value={customPath}
                onChange={(e) => setCustomPath(e.target.value)}
                placeholder="/path/to/folder"
              />
            </div>
          )}

          {mode === "full" && (
            <div className="warning-banner" role="status" style={{ marginBottom: "1rem" }}>
              Scans the entire disk — may be slow and hit permission errors.
            </div>
          )}
        </div>
      )}

      {scanErr && (
        <div className="action-banner err" role="alert">{scanErr}</div>
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
          <div className="scan-progress-meta scan-progress-meta-stack">
            <div className="scan-progress-row">
              <span>
                <strong>{finished && live?.status === "completed" ? 100 : progress}%</strong>
                {!live?.progressExact && running && live?.status === "running" && (
                  <span className="scan-progress-badge">estimate</span>
                )}
              </span>
              <span>
                {live?.progressExact && live.totalFiles != null
                  ? `${live.filesScanned.toLocaleString()} / ${live.totalFiles.toLocaleString()} files`
                  : `${(live?.filesScanned ?? 0).toLocaleString()} files scanned`}
                {(live?.infectedCount ?? 0) > 0 && (
                  <>
                    {" "}
                    ·{" "}
                    <span style={{ color: "var(--danger)", fontWeight: 600 }}>
                      {live!.infectedCount} threat{live!.infectedCount !== 1 ? "s" : ""}
                    </span>
                  </>
                )}
              </span>
            </div>
            <div className="scan-progress-sub">
              {etaText && (
                <span>
                  {etaText}
                  {etaApprox ? " (approx.)" : ""}
                </span>
              )}
              {fpsText && (
                <span className="scan-progress-fps">{fpsText}</span>
              )}
              {indeterminate && !etaText && running && (
                <span className="scan-progress-sub-muted">Calibrating speed and ETA…</span>
              )}
            </div>
          </div>
          <div className="scan-progress-track">
            <div
              className={`scan-progress-fill ${indeterminate ? "indeterminate" : ""}`}
              style={indeterminate ? undefined : { width: `${Math.min(100, Math.max(2, progress))}%` }}
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
            <>{live.infectedCount} threat{live.infectedCount !== 1 ? "s" : ""} quarantined. {live.filesScanned.toLocaleString()} files scanned.</>
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

function SettingsPanel({
  health,
  loading,
  connectionErr,
  autoStartRealtime,
  onAutoStartRealtimeChange,
  autoStartDaemon,
  onAutoStartDaemonChange,
  autoEnsureCronDefaults,
  onAutoEnsureCronDefaultsChange,
  onRefresh,
}: {
  health: Health | null;
  loading: boolean;
  connectionErr: string | null;
  autoStartRealtime: boolean;
  onAutoStartRealtimeChange: (v: boolean) => void;
  autoStartDaemon: boolean;
  onAutoStartDaemonChange: (v: boolean) => void;
  autoEnsureCronDefaults: boolean;
  onAutoEnsureCronDefaultsChange: (v: boolean) => void;
  onRefresh: (silent?: boolean) => void | Promise<void>;
}) {
  const [openAtLogin, setOpenAtLogin] = useState(false);
  const [loginLoaded, setLoginLoaded] = useState(false);
  const electron = typeof window !== "undefined" && window.clamavGUI?.isElectron;

  useEffect(() => {
    if (!electron || !window.clamavGUI) return;
    void window.clamavGUI.getOpenAtLogin().then((v) => {
      setOpenAtLogin(!!v);
      setLoginLoaded(true);
    });
  }, [electron]);

  return (
    <div className="card fade-in">
      <h2 style={{ marginBottom: "0.25rem" }}>Settings</h2>
      <p className="hint" style={{ marginBottom: "1.25rem" }}>
        Application preferences. ClamAV engine files are edited under the <strong>Config</strong> tab.
      </p>

      <div className="settings-block">
        <p className="section-label">Connection</p>
        <p className="hint" style={{ marginBottom: "0.5rem" }}>
          {connectionErr ? (
            <span style={{ color: "var(--danger)" }}>Cannot reach the local app server.</span>
          ) : loading && !health ? (
            "Loading…"
          ) : health ? (
            <>
              OK · definitions {health.clamav?.freshclamInstalled ? "ready" : "missing"} · daemon{" "}
              {health.clamav?.daemonResponding ? "online" : "offline"}
            </>
          ) : (
            "—"
          )}
        </p>
        <button type="button" className="btn btn-primary" disabled={!!connectionErr} onClick={() => void onRefresh()}>
          ↻ Refresh status
        </button>
      </div>

      <div className="settings-block">
        <p className="section-label">Real-time folder monitor</p>
        <label className="settings-check-row">
          <input
            type="checkbox"
            checked={autoStartRealtime}
            onChange={(e) => {
              const v = e.target.checked;
              onAutoStartRealtimeChange(v);
              try {
                localStorage.setItem("clamav-autort-realtime", v ? "1" : "0");
              } catch {
                /* ignore */
              }
            }}
          />
          <span>Start monitoring automatically when this app opens</span>
        </label>
      </div>

      <div className="settings-block">
        <p className="section-label">ClamAV daemon</p>
        <label className="settings-check-row">
          <input
            type="checkbox"
            checked={autoStartDaemon}
            onChange={(e) => {
              const v = e.target.checked;
              onAutoStartDaemonChange(v);
              try {
                localStorage.setItem("clamav-autostart-daemon", v ? "1" : "0");
              } catch {
                /* ignore */
              }
            }}
          />
          <span>
            When this app opens, try to start the ClamAV scanner daemon if it is not running (same as Dashboard →
            Start).
          </span>
        </label>
        <p className="hint" style={{ margin: "0.5rem 0 0 1.5rem" }}>
          Runs once per app launch. You may be prompted for an administrator password on macOS/Linux if your setup
          requires it.
        </p>
      </div>

      <div className="settings-block">
        <p className="section-label">Scheduled jobs (cron)</p>
        <label className="settings-check-row">
          <input
            type="checkbox"
            checked={autoEnsureCronDefaults}
            onChange={(e) => {
              const v = e.target.checked;
              onAutoEnsureCronDefaultsChange(v);
              try {
                localStorage.setItem("clamav-autostart-cron", v ? "1" : "0");
              } catch {
                /* ignore */
              }
            }}
          />
          <span>
            When this app opens, ensure the default cron jobs exist (nightly <code>freshclam</code> + weekly{" "}
            <code>clamdscan</code> of your scan folder — same presets as the Schedules tab).
          </span>
        </label>
        <p className="hint" style={{ margin: "0.5rem 0 0 1.5rem" }}>
          <strong>macOS / Linux only.</strong> Skips jobs that are already in your crontab. Not available on Windows.
        </p>
      </div>

      {electron ? (
        <div className="settings-block">
          <p className="section-label">Desktop (Electron)</p>
          <label className="settings-check-row">
            <input
              type="checkbox"
              checked={openAtLogin}
              disabled={!loginLoaded}
              onChange={(e) => {
                const v = e.target.checked;
                setOpenAtLogin(v);
                void window.clamavGUI?.setOpenAtLogin(v).then((ok) => setOpenAtLogin(!!ok));
              }}
            />
            <span>Open this app at login</span>
          </label>
        </div>
      ) : (
        <p className="hint" style={{ marginTop: "1rem" }}>
          “Open at login” is available in the desktop (Electron) build.
        </p>
      )}
    </div>
  );
}

type DnsPresetRow = { id: string; label: string; servers: string[] | null };

function DnsPanel({
  health,
  onRefresh,
}: {
  health: Health | null;
  onRefresh: (silent?: boolean) => void | Promise<void>;
}) {
  const [presets, setPresets] = useState<DnsPresetRow[]>([]);
  const [busy, setBusy] = useState(false);
  const [banner, setBanner] = useState<{ ok: boolean; text: string } | null>(null);
  const [cmdLogs, setCmdLogs] = useState<TerminalLogEntry[]>([]);
  const [customPri, setCustomPri] = useState("1.1.1.1");
  const [customSec, setCustomSec] = useState("1.0.0.1");

  const dns = health?.dns;

  useEffect(() => {
    void api("/api/dns/presets")
      .then((r) => (r.ok ? r.json() : null))
      .then((j) => {
        if (j?.items && Array.isArray(j.items)) setPresets(j.items);
      })
      .catch(() => {});
  }, []);

  const apply = async (preset: string) => {
    setBusy(true);
    setBanner(null);
    setCmdLogs([]);
    try {
      const body: Record<string, string> = { preset };
      if (preset === "custom") {
        body.primary = customPri.trim();
        if (customSec.trim()) body.secondary = customSec.trim();
      }
      const r = await api("/api/dns/apply", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const j = (await r.json()) as {
        ok?: boolean;
        error?: string;
        terminalLogs?: TerminalLogEntry[];
        elevated?: boolean;
      };
      const tl = Array.isArray(j.terminalLogs) ? j.terminalLogs : [];
      setCmdLogs(tl);
      if (!r.ok || !j.ok) {
        setBanner({ ok: false, text: j.error || `Request failed (${r.status})` });
        return;
      }
      setBanner({
        ok: true,
        text: j.elevated ? "DNS updated (administrator approval was used)." : "DNS updated.",
      });
      await onRefresh(true);
    } catch (e) {
      setBanner({ ok: false, text: String(e) });
    } finally {
      setBusy(false);
    }
  };

  const presetCards = presets.filter((p) => p.id !== "custom");

  return (
    <div className="card fade-in">
      <h2 style={{ marginBottom: "0.25rem" }}>DNS resolver</h2>
      <p className="hint" style={{ marginBottom: "1rem" }}>
        Switch IPv4 DNS for your active network (Wi‑Fi / Ethernet). <strong>Automatic</strong> uses your router /
        DHCP. On macOS and Windows, changing DNS may prompt for an administrator password. Linux uses{" "}
        <code>nmcli</code> (NetworkManager).
      </p>

      {dns && !dns.supported && (
        <div className="warning-banner" role="status">
          {dns.detail || "DNS control is not available on this system from this app."}
        </div>
      )}

      {dns && dns.supported && (
        <div className="dns-current-card">
          <p className="section-label" style={{ marginBottom: "0.35rem" }}>
            Current
          </p>
          <p className="dns-current-label">{dns.displayLabel}</p>
          {dns.service && (
            <p className="hint" style={{ margin: "0.25rem 0 0" }}>
              Interface / connection: <code>{dns.service}</code> · via {dns.method}
            </p>
          )}
          {!dns.automatic && dns.servers.length > 0 && (
            <p className="hint" style={{ margin: "0.35rem 0 0" }}>
              Servers: <code>{dns.servers.join(", ")}</code>
            </p>
          )}
          {dns.detail ? (
            <p className="hint" style={{ margin: "0.35rem 0 0", color: "var(--warn)" }}>
              {dns.detail}
            </p>
          ) : null}
        </div>
      )}

      {banner && (
        <div className={`action-banner fade-in ${banner.ok ? "ok" : "err"}`} role="status">
          {banner.ok ? "✓ " : "✕ "}
          {banner.text}
        </div>
      )}

      <p className="section-label" style={{ marginTop: "1rem" }}>
        Presets
      </p>
      <div className="dns-preset-grid">
        {presetCards.map((p) => (
          <button
            key={p.id}
            type="button"
            className={`scan-mode-card ${dns?.matchedPreset === p.id ? "selected" : ""}`}
            disabled={busy || !dns?.supported}
            title={p.servers ? p.servers.join(", ") : ""}
            onClick={() => void apply(p.id)}
          >
            <span className="scan-mode-icon">🌐</span>
            <strong>{p.label}</strong>
            {p.servers && <span className="scan-mode-hint">{p.servers.join(" · ")}</span>}
          </button>
        ))}
      </div>

      <p className="section-label" style={{ marginTop: "1rem" }}>
        Custom IPv4
      </p>
      <div className="dns-custom-row">
        <label className="dns-field">
          Primary
          <input
            type="text"
            value={customPri}
            onChange={(e) => setCustomPri(e.target.value)}
            placeholder="e.g. 1.1.1.1"
            spellCheck={false}
            disabled={busy}
          />
        </label>
        <label className="dns-field">
          Secondary (optional)
          <input
            type="text"
            value={customSec}
            onChange={(e) => setCustomSec(e.target.value)}
            placeholder="e.g. 1.0.0.1"
            spellCheck={false}
            disabled={busy}
          />
        </label>
        <button
          type="button"
          className="btn btn-primary dns-custom-apply"
          disabled={busy || !dns?.supported}
          onClick={() => void apply("custom")}
        >
          Apply custom
        </button>
      </div>

      <div style={{ marginTop: "1rem" }}>
        <button
          type="button"
          className="btn btn-ghost"
          disabled={busy || !dns?.supported}
          onClick={() => void apply("automatic")}
        >
          ↺ Reset to automatic (DHCP / router DNS)
        </button>
      </div>

      {busy && (
        <p className="hint" style={{ marginTop: "0.75rem" }}>
          <span className="spinner-inline" aria-hidden />
          Applying…
        </p>
      )}

      <TerminalOutputPanel logs={cmdLogs} />
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
    return "Requires Homebrew. Install it, then reopen this tab.";
  }
  if (st.platform === "linux") {
    return "Use your package manager (apt, dnf, etc.) — see commands below.";
  }
  if (st.platform === "win32") {
    return "Download the installer from clamav.net/downloads.";
  }
  return "Install ClamAV manually, then check the Dashboard.";
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
        ? "Uninstall ClamAV? You may be prompted for your password."
        : "Uninstall ClamAV and remove all files?";
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
      <div className="card fade-in">
        <h2 style={{ marginBottom: "0.25rem" }}>Auto-install</h2>
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
    <div className="card fade-in">
      <h2 style={{ marginBottom: "0.25rem" }}>Auto-install</h2>
      <p className="hint" style={{ marginBottom: "0.75rem" }}>
        macOS with Homebrew: run all steps from this app. Other systems: see commands below.
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
          ClamAV is ready. Check the <strong>Dashboard</strong> for status.
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
        Remove ClamAV from your system.
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
    <div className="card fade-in">
      <h2 style={{ marginBottom: "0.25rem" }}>Instructions &amp; About</h2>
      <p className="hint" style={{ marginBottom: "1rem" }}>
        ClamAV Control is a GUI for the open-source ClamAV antivirus engine.
        It manages scanning, definitions, quarantine, and scheduling from one place.
      </p>

      <details className="help-section" open>
        <summary>Getting started</summary>
        <div className="help-body">
          <ol className="instructions-steps">
            <li><strong>Install ClamAV</strong> — use the Auto-install tab (macOS / Homebrew) or your OS package manager.</li>
            <li><strong>Check the Dashboard</strong> — all indicators should be green.</li>
            <li><strong>Update definitions</strong> — click “Update definitions” to fetch the latest signatures.</li>
            <li><strong>Run a scan</strong> — go to Scan, pick Standard / Full / Custom, and start.</li>
          </ol>
        </div>
      </details>

      <details className="help-section">
        <summary>Install by operating system</summary>
        <div className="help-body">
          <div className="instructions-os">
            <section>
              <h3>macOS</h3>
              <p>Use the <strong>Auto-install</strong> tab or manually: <code>brew install clamav</code> then <code>brew services start clamav</code>.</p>
            </section>
            <section>
              <h3>Windows</h3>
              <p>Download the installer from <a href="https://www.clamav.net/downloads" target="_blank" rel="noreferrer">clamav.net</a>. Use the Dashboard to start the daemon.</p>
            </section>
            <section>
              <h3>Linux</h3>
              <p><code>apt install clamav clamav-daemon</code> or equivalent. Real-time scanning via <code>clamonacc</code> may be available.</p>
            </section>
          </div>
        </div>
      </details>

      <details className="help-section">
        <summary>App tabs explained</summary>
        <div className="help-body">
          <dl className="tab-explainer">
            <dt>Dashboard</dt><dd>Status overview. Start/stop daemon, update definitions, toggle firewall.</dd>
            <dt>Auto-install</dt><dd>One-click install/uninstall on macOS. Manual commands for other platforms.</dd>
            <dt>Scan</dt><dd>Standard, Full, or Custom scan with live file log. Threats are auto-quarantined.</dd>
            <dt>Quarantine</dt><dd>Review, restore, or delete quarantined files.</dd>
            <dt>Schedules</dt><dd>Cron jobs for automatic updates and scans (macOS/Linux).</dd>
            <dt>Config</dt><dd>Edit ClamAV config files in Guided or Raw mode.</dd>
            <dt>DNS</dt><dd>Optional resolver presets (OpenDNS, Google, Cloudflare, DHCP, custom) for the active network.</dd>
            <dt>Settings</dt><dd>Refresh status, auto-start real-time monitoring, optional daemon/cron setup on app open, open-at-login (desktop).</dd>
          </dl>
        </div>
      </details>

      <details className="help-section">
        <summary>Passwords &amp; privileges</summary>
        <div className="help-body">
          <p>Commands run as your user first. On permission error, the app retries with elevation:</p>
          <ul>
            <li><strong>macOS</strong> — admin password dialog (never <code>sudo brew</code>).</li>
            <li><strong>Linux</strong> — <code>pkexec</code> prompt.</li>
            <li><strong>Windows</strong> — UAC elevation.</li>
          </ul>
        </div>
      </details>

      <details className="help-section">
        <summary>Official resources</summary>
        <div className="help-body">
          <ul className="instructions-links">
            <li><a href="https://www.clamav.net/downloads" target="_blank" rel="noreferrer">ClamAV downloads</a></li>
            <li><a href="https://docs.clamav.net/" target="_blank" rel="noreferrer">ClamAV documentation</a></li>
          </ul>
        </div>
      </details>
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
    <div className="card fade-in">
      <h2 style={{ marginBottom: "0.25rem" }}>Quarantine</h2>
      <p className="hint" style={{ marginBottom: "0.75rem" }}>
        Infected files are moved here automatically. Delete or restore as needed.
        {dir && (
          <>
            <br />
            Quarantine folder: <code>{dir}</code>
          </>
        )}
      </p>

      {msg && (
        <div className={`action-banner fade-in ${msg.ok ? "ok" : "err"}`} role="status">
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
            No quarantined files.
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

function RealtimePanel({
  health,
  onRefresh,
}: {
  health: Health | null;
  onRefresh: (silent?: boolean) => void | Promise<void>;
}) {
  const [busy, setBusy] = useState(false);
  const [events, setEvents] = useState<RtEvent[]>([]);
  const [status, setStatus] = useState(health?.realtimeMonitor ?? null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const logRef = useRef<HTMLDivElement>(null);
  const autoScrollRef = useRef(true);
  const esRef = useRef<EventSource | null>(null);

  const fetchStatus = useCallback(async () => {
    try {
      const r = await api("/api/realtime/status");
      if (r.ok) {
        const s = await r.json();
        setStatus(s);
      }
    } catch { /* ignore */ }
  }, []);

  useEffect(() => { void fetchStatus(); }, [fetchStatus]);

  useEffect(() => {
    if (health?.realtimeMonitor) setStatus(health.realtimeMonitor);
  }, [health?.realtimeMonitor]);

  const connectStream = useCallback(() => {
    esRef.current?.close();
    const es = new EventSource("/api/realtime/stream");
    esRef.current = es;
    es.onmessage = (ev) => {
      try {
        const m = JSON.parse(ev.data);
        if (m.type === "snapshot") {
          setStatus(m);
          return;
        }
        if (m.type === "stopped") {
          void fetchStatus();
          return;
        }
        setEvents((prev) => {
          const next = [...prev, m as RtEvent];
          return next.length > 200 ? next.slice(-200) : next;
        });
        if (m.status === "threat") void onRefresh(true);
      } catch { /* ignore */ }
    };
    es.onerror = () => {
      es.close();
      esRef.current = null;
    };
    return es;
  }, [fetchStatus, onRefresh]);

  useEffect(() => {
    if (status?.running) {
      const es = connectStream();
      return () => es.close();
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status?.running]);

  useEffect(() => {
    const el = logRef.current;
    if (!el || !autoScrollRef.current) return;
    el.scrollTop = el.scrollHeight;
  }, [events]);

  const handleScroll = () => {
    const el = logRef.current;
    if (!el) return;
    autoScrollRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < 48;
  };

  const startMonitor = async () => {
    setBusy(true);
    setMsg(null);
    setEvents([]);
    try {
      const r = await api("/api/realtime/start", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
      const j = await r.json();
      if (j.ok) {
        setMsg({ ok: true, text: `Monitoring started (${j.method})` });
        void fetchStatus();
        void onRefresh(true);
      } else {
        setMsg({ ok: false, text: j.error || "Failed to start" });
      }
    } catch (e) {
      setMsg({ ok: false, text: String(e) });
    } finally {
      setBusy(false);
    }
  };

  const stopMonitor = async () => {
    setBusy(true);
    setMsg(null);
    try {
      const r = await api("/api/realtime/stop", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
      const j = await r.json();
      if (j.ok) {
        setMsg({ ok: true, text: "Monitoring stopped" });
        esRef.current?.close();
        esRef.current = null;
        void fetchStatus();
        void onRefresh(true);
      } else {
        setMsg({ ok: false, text: j.error || "Failed to stop" });
      }
    } catch (e) {
      setMsg({ ok: false, text: String(e) });
    } finally {
      setBusy(false);
    }
  };

  const running = status?.running ?? false;
  const method = status?.method ?? null;
  const methodLabel: Record<string, string> = {
    fswatch: "macOS fswatch (ESF)",
    inotifywait: "Linux inotifywait",
    "node-fswatch": "Node.js fs.watch",
  };

  return (
    <div className="card fade-in">
      <h2 style={{ marginBottom: "0.25rem" }}>Real-time monitoring</h2>
      <p className="hint" style={{ marginBottom: "1rem" }}>
        Watches your key folders for new or changed files and scans them instantly with ClamAV.
        Threats are auto-quarantined.
      </p>

      <div className="rt-status-row">
        <span className={`status-pill ${running ? "ok" : "wait"}`}>
          <span className="dot" aria-hidden />
          {running ? "Active" : "Inactive"}
          {method && running && <span className="status-pill-muted">{methodLabel[method] ?? method}</span>}
        </span>
        {running && status && (
          <>
            <span className="rt-stat">{status.filesScanned.toLocaleString()} scanned</span>
            <span className={`rt-stat ${status.threatsFound > 0 ? "rt-stat-threat" : ""}`}>
              {status.threatsFound} threat{status.threatsFound !== 1 ? "s" : ""}
            </span>
            {status.startedAt && (
              <span className="rt-stat rt-stat-muted">since {new Date(status.startedAt).toLocaleTimeString()}</span>
            )}
          </>
        )}
      </div>

      {msg && (
        <div className={`action-banner fade-in ${msg.ok ? "ok" : "err"}`} role="status">
          {msg.ok ? "✓ " : "✕ "}{msg.text}
        </div>
      )}

      {status?.error && !msg && (
        <div className="action-banner fade-in err" role="alert">
          ✕ {status.error}
        </div>
      )}

      <div className="action-grid" style={{ marginBottom: "1rem" }}>
        {!running && (
          <button type="button" className="btn btn-primary" onClick={startMonitor} disabled={busy}>
            {busy ? <><span className="spinner-inline" aria-hidden />Starting…</> : "▶ Start monitoring"}
          </button>
        )}
        {running && (
          <button type="button" className="btn btn-danger" onClick={stopMonitor} disabled={busy}>
            ■ Stop monitoring
          </button>
        )}
        <button type="button" className="btn btn-ghost" onClick={() => void fetchStatus()} disabled={busy}>
          ↻ Refresh
        </button>
      </div>

      {running && status?.watchedDirs && status.watchedDirs.length > 0 && (
        <details className="help-section" style={{ marginBottom: "0.75rem" }}>
          <summary>Watched folders ({status.watchedDirs.length})</summary>
          <div className="help-body">
            <div className="rt-dirs-list">
              {status.watchedDirs.map((d) => (
                <div key={d} className="path-chip">{d}</div>
              ))}
            </div>
          </div>
        </details>
      )}

      {(events.length > 0 || running) && (
        <div className="rt-log" ref={logRef} onScroll={handleScroll}>
          {events.length === 0 && running && (
            <div className="scan-log-line scan-log-info">Waiting for file events…</div>
          )}
          {events.map((evt, i) => {
            if (evt.status === "info") {
              return <div key={i} className="scan-log-line scan-log-info">{evt.detail}</div>;
            }
            const cls =
              evt.status === "threat" ? "scan-log-found"
              : evt.status === "error" ? "scan-log-skip"
              : evt.status === "scanning" ? "scan-log-info"
              : "scan-log-ok";
            const tag =
              evt.status === "threat" ? "THREAT"
              : evt.status === "error" ? "ERROR"
              : evt.status === "scanning" ? "SCAN"
              : "OK";
            const fname = evt.file ? evt.file.split("/").pop() || evt.file : "";
            return (
              <div key={i} className={`scan-log-line ${cls}`} title={evt.file || undefined}>
                <span className="scan-log-tag">{tag}</span>
                <span className="scan-log-path">{fname}</span>
                {evt.detail && <span className="scan-log-detail">{evt.detail}</span>}
                <span className="rt-event-time">{new Date(evt.ts).toLocaleTimeString()}</span>
              </div>
            );
          })}
          {running && <div className="scan-log-cursor" />}
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
      <div className="card fade-in">
        <h2 style={{ marginBottom: "0.25rem" }}>Schedules</h2>
        <p className="hint">
          Cron is not available on Windows. Use <strong>Task Scheduler</strong> to run{" "}
          <code>freshclam</code> or <code>clamdscan</code> on a schedule. Use the Dashboard for one-off updates
          and scans.
        </p>
      </div>
    );
  }

  return (
    <div className="card fade-in">
      <h2 style={{ marginBottom: "0.25rem" }}>Schedules</h2>

      <div className={`schedule-status-banner ${jobs.length > 0 ? "has-jobs" : ""}`}>
        <div>
          <div className="count" aria-live="polite">
            {jobs.length}
          </div>
        </div>
        <div className="label">
          {jobs.length === 0
            ? "No scheduled jobs. Add one below."
            : jobs.length === 1
              ? "1 active job"
              : `${jobs.length} active jobs`}
        </div>
      </div>

      <p className="hint" style={{ marginBottom: "1rem" }}>
        Cron format: min hour dom month dow. Presets use your scan folder path.
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
