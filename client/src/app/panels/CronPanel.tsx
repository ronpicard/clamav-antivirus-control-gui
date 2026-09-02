import { useCallback, useEffect, useState } from "react";
import { CalendarClock, Plus, RefreshCw } from "lucide-react";
import { api } from "../api";
import { EmptyState } from "../components";
import type { CronJob, Health } from "../types";

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

export function CronPanel() {
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
        <p className="hint">
          Cron is not available on Windows. Use <strong>Task Scheduler</strong> to run{" "}
          <code>freshclam</code> or <code>clamdscan</code> on a schedule. Use the Status page for one-off updates
          and scans.
        </p>
      </div>
    );
  }

  return (
    <div className="card fade-in">
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

      <p className="hint cron-format-hint">
        Cron format: min hour dom month dow. Presets use your scan folder path.
      </p>

      <p className="section-label">Quick presets</p>
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
            <span className="preset-desc">{p.desc}</span>
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
        className="cron-input"
      />
      <label htmlFor="cmd">Shell command</label>
      <input
        id="cmd"
        type="text"
        value={command}
        onChange={(e) => setCommand(e.target.value)}
        className="cron-input"
      />
      <label htmlFor="cmt">Note (comment above the job)</label>
      <input
        id="cmt"
        type="text"
        value={comment}
        onChange={(e) => setComment(e.target.value)}
        className="cron-input cron-input-last"
      />
      <div className="action-grid">
        <button type="button" className="btn btn-primary" onClick={add}>
          <Plus size={14} aria-hidden /> Add to crontab
        </button>
        <button type="button" className="btn btn-ghost" onClick={load}>
          <RefreshCw size={14} aria-hidden /> Refresh list
        </button>
      </div>

      {msg && <p className="hint">{msg}</p>}

      <p className="section-label section-gap">Active timer scans</p>
      {jobs.length === 0 && (
        <EmptyState icon={CalendarClock} title="No active jobs yet">
          Use a quick preset above, or write your own schedule and add it to your crontab.
        </EmptyState>
      )}
      {jobs.length > 0 && (
        <div className="cron-job-list">
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
        <pre className="log-box log-box-tall">
          {raw || "(empty)"}
        </pre>
      </details>
    </div>
  );
}
