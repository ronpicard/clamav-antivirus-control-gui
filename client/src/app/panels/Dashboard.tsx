import { useEffect, useRef, useState } from "react";
import { Download, Play, RefreshCw, RotateCw, Square } from "lucide-react";
import { api } from "../api";
import { Banner, TerminalOutputPanel, Toggle } from "../components";
import type { Health, TerminalLogEntry } from "../types";
import type { TabId } from "../navigation";

function RealtimeMonitorSection({
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

  const setRunning = async (next: boolean) => {
    setBusy(true);
    setMsg(null);
    try {
      const r = await api(next ? "/api/realtime/start" : "/api/realtime/stop", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      const j = await r.json();
      if (j.ok) {
        setMsg({ ok: true, text: next ? `Real-time started (${j.method})` : "Real-time stopped" });
        void onRefresh(true);
      } else {
        setMsg({ ok: false, text: j.error || (next ? "Failed to start" : "Failed to stop") });
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
      <p className="hint dash-section-hint">
        Same as the Real-time tab — watches key folders and scans new or changed files.
      </p>
      {msg && <Banner ok={msg.ok}>{msg.text}</Banner>}
      <div className="row">
        <Toggle
          checked={running}
          disabled={!!controlsDisabled || busy}
          onChange={(next) => void setRunning(next)}
          label={running ? "Monitoring on" : "Monitoring off"}
        />
        {busy && <span className="spinner-inline" aria-hidden />}
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

  const c = health?.clamav;
  const fw = health?.firewall;
  const svc = health?.clamdService;

  const fwOk = fw?.active === true;
  const fwUnknown = fw?.active === null || fw?.active === undefined;

  const daemonResponding = !!c?.daemonResponding;
  const serviceRunning = !!svc?.running;
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
  const daemonRunning = daemonResponding || serviceRunning;

  const dns = health?.dns;
  const dnsPillOk = dns?.supported && dns.ok !== false;
  const dnsSummary = dnsDashboardLine(dns);

  const anyBusy = svcBusy || !!busy || defStreaming;

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
          <div className="status-grid">
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
              state={fwOk ? "ok" : fw?.active === false ? "bad" : "wait"}
              label="Firewall"
              detail={fwOk ? "on" : fw?.active === false ? "off" : "unknown"}
              title={fw?.detail}
            />
            <StatusPill
              state={health.realtimeMonitor?.running ? "ok" : "wait"}
              label="Real-time"
              detail={health.realtimeMonitor?.running ? "active" : "off"}
              onOpen={() => onNavigate("realtime")}
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

          <RealtimeMonitorSection
            running={!!health.realtimeMonitor?.running}
            onRefresh={onRefresh}
            controlsDisabled={anyBusy}
          />

          {svcBanner && <Banner ok={svcBanner.ok}>{svcBanner.text}</Banner>}

          {(svcBusy || busy) && (
            <p className="hint dash-busy-hint">
              <span className="spinner-inline" aria-hidden />
              {svcBusy ? "Running command…" : busy}
            </p>
          )}

          <div className="dashboard-sections">
            <div className="dash-section">
              <p className="section-label">Firewall</p>
              <Toggle
                checked={fwOk}
                disabled={anyBusy || fwUnknown}
                onChange={(next) => void firewallAction(next ? "on" : "off")}
                label={fwOk ? "Firewall on" : fwUnknown ? "Firewall state unknown" : "Firewall off"}
              />
            </div>

            <div className="dash-section">
              <p className="section-label">Scanner daemon</p>
              <div className="action-grid">
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
              </div>
            </div>

            <div className="dash-section">
              <p className="section-label">Quick actions</p>
              <div className="action-grid">
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={anyBusy}
                  onClick={runFreshclam}
                >
                  <Download size={14} aria-hidden /> Update definitions
                </button>
                <button
                  type="button"
                  className="btn btn-ghost"
                  disabled={!!busy || defStreaming}
                  onClick={() => void onRefresh(true)}
                >
                  <RefreshCw size={14} aria-hidden /> Refresh
                </button>
              </div>
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
