import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import { TerminalOutputPanel } from "../components";
import type { Health, InstallStatus, TerminalLogEntry } from "../types";

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

function ManualStepList({ steps, onCopy }: { steps: { title: string; command: string }[]; onCopy: (cmd: string) => void }) {
  return (
    <ul className="hint manual-step-list">
      {steps.map((m) => (
        <li key={m.title} className="manual-step">
          <strong>{m.title}</strong>
          <div className="manual-step-cmd">
            <pre className="log-box manual-step-pre">{m.command}</pre>
            <button type="button" className="btn btn-ghost manual-step-copy" onClick={() => onCopy(m.command)}>
              Copy
            </button>
          </div>
        </li>
      ))}
    </ul>
  );
}

export function AutoInstallPanel({
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
      <p className="hint card-intro">
        macOS with Homebrew: run all steps from this app. Other systems: see commands below.
      </p>

      {availabilityNote && (
        <div className="warning-banner" role="status">
          <strong>Not available here:</strong> {availabilityNote}
        </div>
      )}

      <div className="row install-checks">
        {st.platform === "darwin" && (
          <span className={`status-pill ${st.brew.clamavInstalled ? "ok" : "bad"}`}>
            <span className="dot" aria-hidden /> Homebrew formula
          </span>
        )}
        <span className={`status-pill ${st.paths.listenerConfigured ? "ok" : "bad"}`}>
          <span className="dot" aria-hidden /> Daemon config (socket)
        </span>
        <span className={`status-pill ${st.binaries.freshclamOk ? "ok" : "bad"}`}>
          <span className="dot" aria-hidden /> freshclam on PATH
        </span>
        <span className={`status-pill ${st.binaries.clamdscanOk ? "ok" : "bad"}`}>
          <span className="dot" aria-hidden /> clamdscan on PATH
        </span>
        <span className={`status-pill ${health?.clamav.daemonResponding ? "ok" : "wait"}`}>
          <span className="dot" aria-hidden /> Daemon responding
        </span>
      </div>

      {ready && (
        <p className="hint install-ready-note">
          ClamAV is ready. Check the <strong>Dashboard</strong> for status.
        </p>
      )}

      {st.canAutomate && (
        <div className="row install-actions">
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
          <h3 className="install-subhead">Install commands (run in Terminal)</h3>
          <ManualStepList steps={st.manualSteps} onCopy={(cmd) => void copyCmd(cmd)} />
        </>
      )}

      {st.canAutomate && st.brew.path && (
        <p className="hint install-brew-note">
          Homebrew: <code>{st.brew.path}</code>
          {st.brew.version ? ` · ${st.brew.version}` : ""}
          <br />
          Config file: <code>{st.paths.clamdConf}</code>
        </p>
      )}

      <p className="section-label section-gap">Uninstall</p>
      <p className="hint uninstall-note">Remove ClamAV from your system.</p>
      {showAutomatedUninstall && (
        <div className="row uninstall-actions">
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
          <h3 className="install-subhead">
            {showAutomatedUninstall ? "Or uninstall manually" : "Uninstall commands"}
          </h3>
          <ManualStepList steps={un.manualSteps} onCopy={(cmd) => void copyCmd(cmd)} />
        </>
      )}

      {busy && <p className="hint">{busy}</p>}
      <TerminalOutputPanel logs={cmdLogs} />
      {log && <pre className="log-box">{log}</pre>}

      <div className="row install-refresh-row">
        <button type="button" className="btn btn-ghost" onClick={load} disabled={!!busy || uninstallBusy}>
          Refresh setup checks
        </button>
      </div>
    </div>
  );
}
