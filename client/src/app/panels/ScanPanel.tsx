import { useCallback, useEffect, useRef, useState } from "react";
import { FolderOpen, HardDrive, Play, Search } from "lucide-react";
import { api } from "../api";
import { Banner } from "../components";
import {
  EMPTY_SCAN_SESSION,
  type Health,
  type ScanHistoryEntry,
  type ScanLine,
  type ScanMode,
  type ScanSessionState,
  type ScanStreamState,
} from "../types";

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

export function ScanPanel({
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
  const reconnectsRef = useRef(0);

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
    reconnectsRef.current = 0;
    // Give up only after the browser's own reconnect attempts keep failing, so
    // a brief network blip (or a throttled background tab) doesn't abandon a
    // scan that is still running server-side.
    const MAX_RECONNECTS = 6;
    const es = new EventSource(`/api/scan/stream?id=${encodeURIComponent(activeScanId)}`);
    esRef.current = es;
    const giveUp = (reason: string) => {
      es.close();
      esRef.current = null;
      setActiveScanId(null);
      if (!streamDoneRef.current) setScanErr(reason);
    };
    es.onmessage = (ev) => {
      try {
        const m = JSON.parse(ev.data) as ScanStreamState & { type: string; findings?: string[] };
        setPendingStart(false);
        reconnectsRef.current = 0;
        setScanErr(null); // clear any transient "reconnecting" notice
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
      if (streamDoneRef.current) {
        es.close();
        esRef.current = null;
        return;
      }
      // readyState CONNECTING means the browser is auto-reconnecting; let it,
      // up to a bound. CLOSED means a fatal error (e.g. the session expired and
      // the server returned 404) — no point retrying.
      if (es.readyState === EventSource.CONNECTING) {
        reconnectsRef.current += 1;
        if (reconnectsRef.current <= MAX_RECONNECTS) {
          setScanErr("Reconnecting to scan…");
          return;
        }
      }
      giveUp("Scan stream disconnected");
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
      {!running && !finished && (
        <div className="fade-in">
          <div className="scan-mode-grid">
            <button
              type="button"
              className={`scan-mode-card ${mode === "quick" ? "selected" : ""}`}
              onClick={() => setMode("quick")}
            >
              <span className="scan-mode-icon"><Search size={22} strokeWidth={1.8} aria-hidden /></span>
              <strong>Standard</strong>
              <span className="scan-mode-hint">Common user folders</span>
            </button>
            <button
              type="button"
              className={`scan-mode-card ${mode === "full" ? "selected" : ""}`}
              onClick={() => setMode("full")}
            >
              <span className="scan-mode-icon"><HardDrive size={22} strokeWidth={1.8} aria-hidden /></span>
              <strong>Full system</strong>
              <span className="scan-mode-hint">Entire disk</span>
            </button>
            <button
              type="button"
              className={`scan-mode-card ${mode === "custom" ? "selected" : ""}`}
              onClick={() => setMode("custom")}
            >
              <span className="scan-mode-icon"><FolderOpen size={22} strokeWidth={1.8} aria-hidden /></span>
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
            <div className="scan-custom-path">
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
            <div className="warning-banner" role="status">
              Scans the entire disk — may be slow and hit permission errors.
            </div>
          )}
        </div>
      )}

      {scanErr && (
        <Banner ok={false} role="alert">{scanErr}</Banner>
      )}

      <div className="action-grid scan-actions">
        {!running && !finished && (
          <button type="button" className="btn btn-primary" onClick={startScan} disabled={pendingStart}>
            {pendingStart ? (
              <>
                <span className="spinner-inline" aria-hidden />
                Starting…
              </>
            ) : (
              <>
                <Play size={14} aria-hidden />
                {mode === "quick" ? "Standard" : mode === "full" ? "Full system" : "Custom"} scan
              </>
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
                    <span className="scan-threat-count">
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
        <details className="advanced" open>
          <summary>Threat details ({live.findings.length})</summary>
          <pre className="log-box log-box-short">
            {live.findings.join("\n")}
          </pre>
        </details>
      )}

      {history.length > 0 && !running && (
        <>
          <p className="section-label section-gap">Recent scans</p>
          <ul className="history-list">
            {history.map((h) => (
              <li key={`${h.id}-${h.endedAt}`} className="history-item">
                <div className="history-meta">
                  {new Date(h.endedAt).toLocaleString()} · {h.mode} · {h.targetLabel} ·{" "}
                  <strong>{h.status}</strong>
                  {h.infectedCount > 0 && (
                    <span className="scan-threat-count"> · {h.infectedCount} infected</span>
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
