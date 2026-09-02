import { RefreshCw } from "lucide-react";
import type { Health } from "../types";

export function SettingsPanel({
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
  return (
    <div className="card fade-in">
      <p className="hint card-intro">
        Application preferences. ClamAV engine files are edited under the <strong>Config</strong> tab.
      </p>

      <div className="settings-block">
        <p className="section-label">Connection</p>
        <p className="hint settings-connection-line">
          {connectionErr ? (
            <span className="text-danger">Cannot reach the local app server.</span>
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
          <RefreshCw size={14} aria-hidden /> Refresh status
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
            When this app opens, try to start the ClamAV scanner engine if it is not running (same as Status →
            Advanced → Start).
          </span>
        </label>
        <p className="hint settings-check-note">
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
        <p className="hint settings-check-note">
          <strong>macOS / Linux only.</strong> Skips jobs that are already in your crontab. Not available on Windows.
        </p>
      </div>

      <p className="hint settings-footnote">
        “Open at login” will return as a native command in a future build.
      </p>
    </div>
  );
}
