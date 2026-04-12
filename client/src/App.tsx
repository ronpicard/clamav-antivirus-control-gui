import { useCallback, useEffect, useState } from "react";

type Health = {
  ok: boolean;
  clamav: {
    clamdscanInstalled: boolean;
    freshclamInstalled: boolean;
    daemonResponding: boolean;
  };
  paths: { clamdConf: string; freshclamConf: string; scanRoot: string };
};

type CronJob = { id: number; line: string; lineIndex: number };

const api = (path: string, init?: RequestInit) => fetch(path, init);

export default function App() {
  const [tab, setTab] = useState<"home" | "config" | "scan" | "cron">("home");
  const [health, setHealth] = useState<Health | null>(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setErr(null);
    try {
      const r = await api("/api/health");
      if (!r.ok) throw new Error(await r.text());
      setHealth(await r.json());
    } catch (e) {
      setErr(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return (
    <>
      <header>
        <h1>ClamAV Control</h1>
        <p className="subtitle">
          Check status, update definitions, edit configs, and schedule scans from the ClamAV Control desktop
          app.
        </p>
      </header>

      <nav className="tabs" aria-label="Sections">
        {(
          [
            ["home", "Dashboard"],
            ["config", "Configuration"],
            ["scan", "Scan"],
            ["cron", "Schedules"],
          ] as const
        ).map(([id, label]) => (
          <button
            key={id}
            type="button"
            className={`tab ${tab === id ? "active" : ""}`}
            onClick={() => setTab(id)}
          >
            {label}
          </button>
        ))}
      </nav>

      {err && (
        <div className="card" style={{ borderColor: "var(--danger)" }}>
          <p style={{ margin: 0, color: "var(--danger)" }}>{err}</p>
          <button type="button" className="btn btn-ghost" style={{ marginTop: "0.75rem" }} onClick={refresh}>
            Retry
          </button>
        </div>
      )}

      {tab === "home" && <Dashboard health={health} loading={loading} onRefresh={refresh} />}
      {tab === "config" && <ConfigPanel />}
      {tab === "scan" && <ScanPanel scanRoot={health?.paths.scanRoot ?? ""} />}
      {tab === "cron" && <CronPanel />}
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
  onRefresh: () => void;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [log, setLog] = useState("");

  const runFreshclam = async () => {
    setBusy("Updating definitions…");
    setLog("");
    try {
      const r = await api("/api/actions/freshclam", { method: "POST" });
      const j = await r.json();
      setLog(JSON.stringify(j, null, 2));
    } catch (e) {
      setLog(String(e));
    } finally {
      setBusy(null);
    }
  };

  const restartClamd = async () => {
    setBusy("Restarting…");
    setLog("");
    try {
      const r = await api("/api/actions/restart-clamd", { method: "POST" });
      const j = await r.json();
      setLog(JSON.stringify(j, null, 2));
    } catch (e) {
      setLog(String(e));
    } finally {
      setBusy(null);
    }
  };

  const c = health?.clamav;

  return (
    <div className="card">
      <h2>Status</h2>
      {loading && <p className="hint">Loading…</p>}
      {!loading && health && (
        <>
          <div className="row" style={{ marginBottom: "1rem" }}>
            <span className={`status-pill ${c?.freshclamInstalled ? "ok" : "bad"}`}>
              {c?.freshclamInstalled ? "●" : "○"} Freshclam
            </span>
            <span className={`status-pill ${c?.clamdscanInstalled ? "ok" : "bad"}`}>
              {c?.clamdscanInstalled ? "●" : "○"} Scanner CLI
            </span>
            <span className={`status-pill ${c?.daemonResponding ? "ok" : "wait"}`}>
              {c?.daemonResponding ? "●" : "○"} Daemon
            </span>
          </div>
          <p className="hint" style={{ marginBottom: "1rem" }}>
            <strong>How to use:</strong> install ClamAV on this computer (e.g. Homebrew on macOS, your distro
            package on Linux, or the Windows installer). Put files to scan in{" "}
            <code>{health.paths.scanRoot}</code> — the app creates that folder if needed. Use the buttons below
            to refresh status or update definitions.
          </p>
          <div className="row">
            <button type="button" className="btn btn-primary" disabled={!!busy} onClick={onRefresh}>
              Refresh status
            </button>
            <button type="button" className="btn btn-ghost" disabled={!!busy} onClick={runFreshclam}>
              Update definitions now
            </button>
            <button type="button" className="btn btn-ghost" disabled={!!busy} onClick={restartClamd}>
              Restart daemon
            </button>
          </div>
          {busy && <p className="hint">{busy}</p>}
          {log && <pre className="log-box">{log}</pre>}
        </>
      )}
    </div>
  );
}

function ConfigPanel() {
  const [which, setWhich] = useState<"clamd" | "freshclam">("clamd");
  const [content, setContent] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setMsg(null);
    try {
      const r = await api(`/api/config/${which}`);
      if (!r.ok) throw new Error(await r.text());
      const j = await r.json();
      setContent(j.content);
    } catch (e) {
      setMsg(String(e));
    } finally {
      setLoading(false);
    }
  }, [which]);

  useEffect(() => {
    load();
  }, [load]);

  const save = async () => {
    setLoading(true);
    setMsg(null);
    try {
      const r = await api(`/api/config/${which}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content }),
      });
      if (!r.ok) throw new Error(await r.text());
      setMsg("Saved. Restart the daemon from the Dashboard if you changed clamd settings.");
    } catch (e) {
      setMsg(String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card">
      <h2>Configuration files</h2>
      <p className="hint" style={{ marginBottom: "1rem" }}>
        Edit the ClamAV config files on this computer. A timestamped <code>.bak</code> file is created on each
        save. Prefer small changes or ask someone you trust — mistakes can stop the scanner from starting.
      </p>
      <div className="row" style={{ marginBottom: "1rem" }}>
        <select
          value={which}
          onChange={(e) => setWhich(e.target.value as "clamd" | "freshclam")}
          style={{ maxWidth: 220 }}
        >
          <option value="clamd">clamd.conf (scanner daemon)</option>
          <option value="freshclam">freshclam.conf (definition updates)</option>
        </select>
        <button type="button" className="btn btn-ghost" onClick={load} disabled={loading}>
          Reload from disk
        </button>
        <button type="button" className="btn btn-primary" onClick={save} disabled={loading}>
          Save
        </button>
      </div>
      <label htmlFor="cfg">File contents</label>
      <textarea id="cfg" value={content} onChange={(e) => setContent(e.target.value)} spellCheck={false} />
      {msg && <p className="hint">{msg}</p>}
    </div>
  );
}

function ScanPanel({ scanRoot }: { scanRoot: string }) {
  const [path, setPath] = useState(".");
  const [busy, setBusy] = useState(false);
  const [out, setOut] = useState("");

  const run = async () => {
    setBusy(true);
    setOut("");
    try {
      const r = await api("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path }),
      });
      const j = await r.json();
      setOut(JSON.stringify(j, null, 2));
    } catch (e) {
      setOut(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card">
      <h2>Scan files</h2>
      <p className="hint" style={{ marginBottom: "1rem" }}>
        Paths are relative to your scan folder: <code>{scanRoot || "open Dashboard first to load"}</code>.
        Example: <code>documents</code> or <code>.</code> for the whole folder.
      </p>
      <label htmlFor="scanpath">Path inside scan folder</label>
      <input
        id="scanpath"
        type="text"
        value={path}
        onChange={(e) => setPath(e.target.value)}
        placeholder="."
        style={{ marginBottom: "1rem" }}
      />
      <button type="button" className="btn btn-primary" onClick={run} disabled={busy}>
        {busy ? "Scanning…" : "Run scan"}
      </button>
      {out && <pre className="log-box">{out}</pre>}
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
      title: "Update definitions nightly",
      desc: "2:15 AM every day",
      schedule: "15 2 * * *",
      command: `freshclam --foreground --stdout >> ${shQuote(freshLog)} 2>&1`,
      comment: "ClamAV GUI: nightly definition update",
    },
    {
      title: "Quick scan weekly",
      desc: "Sunday 3:30 AM — whole scan folder",
      schedule: "30 3 * * 0",
      command: `clamdscan --fdpass -v ${shQuote(root || "/path/to/your/scan/folder")} >> ${shQuote(scanLog)} 2>&1 || true`,
      comment: "ClamAV GUI: weekly scan of scan folder",
    },
  ];
}

function CronPanel() {
  const [jobs, setJobs] = useState<CronJob[]>([]);
  const [raw, setRaw] = useState("");
  const [schedule, setSchedule] = useState("0 3 * * *");
  const [command, setCommand] = useState("freshclam --foreground --stdout");
  const [comment, setComment] = useState("ClamAV GUI job");
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
      setMsg("Job added.");
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
        <h2>Scheduled tasks (cron)</h2>
        <p className="hint">
          Cron is not available on Windows from this app. Use <strong>Task Scheduler</strong> to run{" "}
          <code>freshclam</code> or <code>clamdscan</code> on a schedule, or use the buttons on the Dashboard
          for one-off updates and scans.
        </p>
      </div>
    );
  }

  return (
    <div className="card">
      <h2>Scheduled tasks (cron)</h2>
      <p className="hint" style={{ marginBottom: "1rem" }}>
        Uses your user crontab on Linux and macOS (five fields: minute hour day-of-month month day-of-week).
        You may need to adjust paths or use <code>sudo</code> in the command if your system stores databases
        as a dedicated user. Presets use your scan folder path from the Dashboard.
      </p>

      <h2 style={{ fontSize: "0.95rem", marginTop: "1.25rem" }}>One-click presets</h2>
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

      <label htmlFor="sched">Schedule (five fields)</label>
      <input
        id="sched"
        type="text"
        value={schedule}
        onChange={(e) => setSchedule(e.target.value)}
        style={{ marginBottom: "0.75rem" }}
      />
      <label htmlFor="cmd">Command</label>
      <input
        id="cmd"
        type="text"
        value={command}
        onChange={(e) => setCommand(e.target.value)}
        style={{ marginBottom: "0.75rem" }}
      />
      <label htmlFor="cmt">Label (saved as a comment above the line)</label>
      <input
        id="cmt"
        type="text"
        value={comment}
        onChange={(e) => setComment(e.target.value)}
        style={{ marginBottom: "1rem" }}
      />
      <div className="row">
        <button type="button" className="btn btn-primary" onClick={add}>
          Add job
        </button>
        <button type="button" className="btn btn-ghost" onClick={load}>
          Refresh list
        </button>
      </div>

      {msg && <p className="hint">{msg}</p>}

      <h2 style={{ fontSize: "0.95rem", marginTop: "1.5rem" }}>Current jobs</h2>
      {jobs.length === 0 ? (
        <p className="hint">No jobs yet. Add one above or use a preset.</p>
      ) : (
        <ul className="cron-list">
          {jobs.map((j) => (
            <li key={j.id}>
              <span>{j.line}</span>
              <button type="button" className="btn btn-danger" onClick={() => remove(j.id)}>
                Delete
              </button>
            </li>
          ))}
        </ul>
      )}

      <details style={{ marginTop: "1rem" }}>
        <summary style={{ cursor: "pointer", color: "var(--muted)", fontSize: "0.85rem" }}>
          Show full crontab text
        </summary>
        <pre className="log-box" style={{ maxHeight: 280 }}>
          {raw || "(empty)"}
        </pre>
      </details>
    </div>
  );
}
