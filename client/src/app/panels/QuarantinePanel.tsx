import { useCallback, useEffect, useState } from "react";
import { RefreshCw, ShieldCheck } from "lucide-react";
import { api } from "../api";
import { Banner, EmptyState } from "../components";
import type { QuarantineItem } from "../types";

function formatBytes(b: number): string {
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / (1024 * 1024)).toFixed(1)} MB`;
}

export function QuarantinePanel() {
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
      <p className="hint card-intro">
        Infected files are moved here automatically. Delete or restore as needed.
        {dir && (
          <>
            <br />
            Quarantine folder: <code>{dir}</code>
          </>
        )}
      </p>

      {msg && <Banner ok={msg.ok}>{msg.text}</Banner>}

      <div className="action-grid quarantine-actions">
        <button type="button" className="btn btn-ghost" onClick={() => void load()} disabled={loading}>
          <RefreshCw size={14} aria-hidden /> Refresh
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
        <EmptyState icon={ShieldCheck} title="Quarantine is empty">
          Threats found by scans or real-time monitoring are moved here automatically.
        </EmptyState>
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
