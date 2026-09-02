import { useEffect, useRef, useState } from "react";
import {
  Activity,
  Database,
  Download,
  Flame,
  Play,
  RefreshCw,
  RotateCw,
  ScanLine,
  ShieldAlert,
  ShieldCheck,
  Square,
} from "lucide-react";
import { api } from "../api";
import { Banner, TerminalOutputPanel, Toggle } from "../components";
import { protectionProblems } from "../health";
import type { Health, TerminalLogEntry } from "../types";
import type { TabId } from "../navigation";

function dnsDashboardLine(dns: Health["dns"] | undefined): { text: string; title: string } {
  if (!dns) return { text: "—", title: "" };
  const title = [dns.displayLabel, dns.service && `Interface: ${dns.service}`, dns.detail].filter(Boolean).join("\n");
  if (!dns.supported) return { text: "—", title: title || dns.detail || "" };
  if (dns.automatic || !(dns.servers && dns.servers.length)) return { text: "DHCP", title };
  return { text: dns.servers.join(", "), title };
}

function StatusPill({
  state,
  label,
  detail,
  detailClass = "",
  title,
  onOpen,
}: {
  state: "ok" | "bad" | "wait";
  label: string;
  detail?: string;
  detailClass?: string;
  title?: string;
  onOpen?: () => void;
}) {
  const body = (
    <>
      <span className="dot" aria-hidden />
      {label}
      {detail != null && <span className={`status-pill-muted ${detailClass}`}>{detail}</span>}
    </>
  );
  if (onOpen) {
    return (
      <button
        type="button"
        className={`status-pill status-pill-link ${state}`}
        title={title ? `${title}\nClick to open` : "Click to open"}
        onClick={onOpen}
      >
        {body}
      </button>
    );
  }
  return (
    <span className={`status-pill ${state}`} title={title || undefined}>
      {body}
    </span>
  );
}

export function Dashboard({
  health,
  loading,
  onRefresh,
  onNavigate,
}: {
  health: Health | null;
  loading: boolean;
  onRefresh: (silent?: boolean) => void | Promise<void>;
  onNavigate: (tab: TabId) => void;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [log, setLog] = useState("");
  const [defProgress, setDefProgress] = useState(0);
  const [defStreaming, setDefStreaming] = useState(false);
  const [svcBusy, setSvcBusy] = useState(false);
  const [svcBanner, setSvcBanner] = useState<{ ok: boolean; text: string } | null>(null);
  const [rtBusy, setRtBusy] = useState(false);
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
          const maybeLogs = (m as { terminalLogs?: TerminalLogEntry[] }).terminalLogs;
          if (Array.isArray(maybeLogs)) {
            tl.push(...maybeLogs);
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

  const setRealtime = async (next: boolean) => {
    setRtBusy(true);
    setSvcBanner(null);
    try {
      const r = await api(next ? "/api/realtime/start" : "/api/realtime/stop", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      const j = await r.json();
      if (j.ok) {
        void onRefresh(true);
      } else {
        setSvcBanner({ ok: false, text: j.error || (next ? "Could not turn on real-time protection" : "Could not turn off real-time protection") });
      }
    } catch (e) {
      setSvcBanner({ ok: false, text: String(e) });
    } finally {
      setRtBusy(false);
    }
  };

  const c = health?.clamav;
  const fw = health?.firewall;
  const svc = health?.clamdService;

  const fwOk = fw?.active === true;
  const fwUnknown = fw?.active === null || fw?.active === undefined;

  const installed = !!c?.freshclamInstalled && !!c?.clamdscanInstalled;
  const daemonResponding = !!c?.daemonResponding;
  const serviceRunning = !!svc?.running;
  const daemonRunning = daemonResponding || serviceRunning;
  const rtRunning = !!health?.realtimeMonitor?.running;

  const daemonPillState: "ok" | "wait" = daemonResponding ? "ok" : "wait";
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

  const anyBusy = svcBusy || !!busy || defStreaming || rtBusy;

  // Hero state: shared with the sidebar badge (see app/health.ts).
  const problems = protectionProblems(health ?? null);
  const firstProblem = problems[0];
  const heroFix =
    firstProblem?.id === "install"
      ? { label: "Open Setup", onFix: () => onNavigate("auto-install") }
      : firstProblem?.id === "engine"
        ? { label: "Start engine", onFix: () => void clamdServiceAction("start") }
        : null;
  const protectedNow = problems.length === 0;

  return (
    <div className="card fade-in">
      {loading && (
        <div className="card-loading">
          <p className="hint">
            <span className="spinner-inline" aria-hidden />
            Checking your system…
          </p>
          <div className="skeleton-block" aria-hidden />
        </div>
      )}
      {!loading && health && (
        <>
          <div className="hero">
            <div className={`hero-shield ${protectedNow ? "ok" : "warn"}`} aria-hidden>
              {protectedNow ? <ShieldCheck size={44} strokeWidth={1.6} /> : <ShieldAlert size={44} strokeWidth={1.6} />}
            </div>
            <h2 className="hero-title">{protectedNow ? "You're protected" : "Attention needed"}</h2>
            <p className="hero-sub">
              {protectedNow
                ? "Everything is running. Scans and real-time protection are active."
                : firstProblem.text}
            </p>
            <div className="hero-actions">
              <button
                type="button"
                className="btn btn-primary hero-scan-btn"
                onClick={() => onNavigate("scan")}
              >
                <ScanLine size={17} aria-hidden /> Scan now
              </button>
              {heroFix && (
                <button
                  type="button"
                  className="btn btn-ghost"
                  disabled={anyBusy}
                  onClick={heroFix.onFix}
                >
                  {heroFix.label}
                </button>
              )}
            </div>
          </div>

          {svcBanner && <Banner ok={svcBanner.ok}>{svcBanner.text}</Banner>}

          {(svcBusy || busy) && (
            <p className="hint dash-busy-hint">
              <span className="spinner-inline" aria-hidden />
              {svcBusy ? "Running command…" : busy}
            </p>
          )}

          <div className="feature-list">
            <div className="feature-row">
              <span className={`feature-icon ${rtRunning ? "on" : ""}`} aria-hidden>
                <Activity size={18} strokeWidth={1.8} />
              </span>
              <div className="feature-text">
                <strong>Real-time protection</strong>
                <span>Scans new and changed files the moment they appear</span>
              </div>
              <Toggle
                checked={rtRunning}
                disabled={anyBusy || !installed}
                onChange={(next) => void setRealtime(next)}
                ariaLabel="Real-time protection"
              />
            </div>

            <div className="feature-row">
              <span className={`feature-icon ${fwOk ? "on" : ""}`} aria-hidden>
                <Flame size={18} strokeWidth={1.8} />
              </span>
              <div className="feature-text">
                <strong>Firewall</strong>
                <span>
                  {fwUnknown
                    ? "State unknown on this system"
                    : "Blocks unwanted incoming connections"}
                </span>
              </div>
              <Toggle
                checked={fwOk}
                disabled={anyBusy || fwUnknown}
                onChange={(next) => void firewallAction(next ? "on" : "off")}
                ariaLabel="Firewall"
              />
            </div>

            <div className="feature-row">
              <span className={`feature-icon ${installed ? "on" : ""}`} aria-hidden>
                <Database size={18} strokeWidth={1.8} />
              </span>
              <div className="feature-text">
                <strong>Virus definitions</strong>
                <span>Keep threat signatures up to date</span>
              </div>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                disabled={anyBusy || !installed}
                onClick={runFreshclam}
              >
                <Download size={13} aria-hidden /> Update
              </button>
            </div>
          </div>

          {defStreaming && (
            <div className="scan-progress-wrap fade-in">
              <div className="scan-progress-meta">
                <span><strong>{defProgress}%</strong></span>
                <span>Updating definitions…</span>
              </div>
              <div className="scan-progress-track">
                <div className="scan-progress-fill" style={{ width: `${defProgress}%` }} />
              </div>
            </div>
          )}

          <details className="advanced dash-advanced">
            <summary>Advanced</summary>

            <div className="status-grid dash-advanced-pills">
              <StatusPill
                state={c?.freshclamInstalled ? "ok" : "bad"}
                label="Definitions"
                detail="freshclam"
                onOpen={() => onNavigate("auto-install")}
              />
              <StatusPill
                state={c?.clamdscanInstalled ? "ok" : "bad"}
                label="Scanner"
                detail="clamdscan"
                onOpen={() => onNavigate("auto-install")}
              />
              <StatusPill
                state={daemonPillState}
                label="Daemon"
                detail={daemonResponding ? "online" : "offline"}
                title={daemonPillTitle || undefined}
              />
              <StatusPill
                state={dnsPillOk ? "ok" : dns?.supported === false ? "bad" : "wait"}
                label="DNS"
                detail={dnsSummary.text}
                detailClass="dns-pill-nums"
                title={dnsSummary.title || undefined}
                onOpen={() => onNavigate("dns")}
              />
            </div>

            <p className="section-label">Scanner engine (clamd)</p>
            <div className="action-grid dash-advanced-actions">
              {daemonRunning ? (
                <button
                  type="button"
                  className="btn btn-ghost"
                  disabled={anyBusy}
                  onClick={() => void clamdServiceAction("stop")}
                >
                  <Square size={14} aria-hidden /> Stop
                </button>
              ) : (
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={anyBusy}
                  onClick={() => void clamdServiceAction("start")}
                >
                  <Play size={14} aria-hidden /> Start
                </button>
              )}
              <button
                type="button"
                className="btn btn-ghost"
                disabled={anyBusy}
                onClick={() => void clamdServiceAction("restart")}
              >
                <RotateCw size={14} aria-hidden /> Restart
              </button>
              <button
                type="button"
                className="btn btn-ghost"
                disabled={!!busy || defStreaming}
                onClick={() => void onRefresh(true)}
              >
                <RefreshCw size={14} aria-hidden /> Refresh status
              </button>
            </div>

            <TerminalOutputPanel logs={cmdLogs} />
            {log && (
              <pre ref={logPreRef} className="log-box log-box-live">
                {log}
              </pre>
            )}
          </details>
        </>
      )}
    </div>
  );
}
