import { useCallback, useEffect, useRef, useState } from "react";
import { EyeOff, Play, RefreshCw, Square } from "lucide-react";
import { api } from "../api";
import { Banner, EmptyState } from "../components";
import type { Health, RtEvent } from "../types";

export function RealtimePanel({
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
      <p className="hint card-intro">
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

      {msg && <Banner ok={msg.ok}>{msg.text}</Banner>}

      {status?.error && !msg && (
        <Banner ok={false} role="alert">{status.error}</Banner>
      )}

      <div className="action-grid rt-actions">
        {!running && (
          <button type="button" className="btn btn-primary" onClick={startMonitor} disabled={busy}>
            {busy ? (
              <>
                <span className="spinner-inline" aria-hidden />
                Starting…
              </>
            ) : (
              <>
                <Play size={14} aria-hidden /> Start monitoring
              </>
            )}
          </button>
        )}
        {running && (
          <button type="button" className="btn btn-danger" onClick={stopMonitor} disabled={busy}>
            <Square size={14} aria-hidden /> Stop monitoring
          </button>
        )}
        <button type="button" className="btn btn-ghost" onClick={() => void fetchStatus()} disabled={busy}>
          <RefreshCw size={14} aria-hidden /> Refresh
        </button>
      </div>

      {running && status?.watchedDirs && status.watchedDirs.length > 0 && (
        <details className="help-section rt-dirs-section">
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

      {!running && events.length === 0 && (
        <EmptyState icon={EyeOff} title="Monitoring is off">
          Start monitoring to watch your folders and see live scan events here.
        </EmptyState>
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
