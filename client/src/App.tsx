import { useCallback, useEffect, useRef, useState } from "react";
import { AppNavigation, NAV_ITEMS, type TabId } from "./app/navigation";
import { api } from "./app/api";
import { EMPTY_SCAN_SESSION, type Health, type ScanSessionState } from "./app/types";
import { Dashboard } from "./app/panels/Dashboard";
import { ScanPanel } from "./app/panels/ScanPanel";
import { RealtimePanel } from "./app/panels/RealtimePanel";
import { QuarantinePanel } from "./app/panels/QuarantinePanel";
import { AutoInstallPanel } from "./app/panels/AutoInstallPanel";
import { CronPanel } from "./app/panels/CronPanel";
import { ConfigPanel } from "./app/panels/ConfigPanel";
import { DnsPanel } from "./app/panels/DnsPanel";
import { SettingsPanel } from "./app/panels/SettingsPanel";
import { InstructionsPanel } from "./app/panels/InstructionsPanel";

export type { TerminalLogEntry } from "./app/types";

export default function App() {
  const [tab, setTab] = useState<TabId>("home");
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

  const activeTab = NAV_ITEMS.find((item) => item.id === tab) ?? NAV_ITEMS[0];
  const coreProtectionReady =
    !!health?.clamav.freshclamInstalled &&
    !!health.clamav.clamdscanInstalled &&
    !!health.clamav.daemonResponding;

  return (
    <div className="app-shell">
      <AppNavigation
        activeTab={tab}
        protectionReady={coreProtectionReady}
        loading={loading}
        onSelect={setTab}
      />
      <main className="app-main">
        <header className="page-header">
          <div>
            <div className="page-eyebrow">{activeTab.group}</div>
            <h1>{activeTab.label}</h1>
            <p>{activeTab.title}</p>
          </div>
        </header>

        {err && (
          <div className="card card-error" role="alert">
            <h2 className="card-error-title">Cannot reach the app</h2>
            <p className="card-error-detail">{err}</p>
            <button type="button" className="btn btn-primary card-error-retry" onClick={() => void refresh()}>
              Try again
            </button>
          </div>
        )}

        <div
          className={`panel-wrap panel-wrap-flex ${tab === "scan" ? "scan-panel-hidden" : ""}`}
          key={tab === "scan" ? "scan-persistent" : tab}
        >
          {tab === "home" && (
            <Dashboard health={health} loading={loading} onRefresh={refresh} onNavigate={setTab} />
          )}
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
      </main>
    </div>
  );
}
