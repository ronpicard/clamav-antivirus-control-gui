import { useEffect, useState } from "react";
import { Globe, RotateCcw } from "lucide-react";
import { api } from "../api";
import { Banner, TerminalOutputPanel } from "../components";
import type { Health, TerminalLogEntry } from "../types";

type DnsPresetRow = { id: string; label: string; servers: string[] | null };

export function DnsPanel({
  health,
  onRefresh,
}: {
  health: Health | null;
  onRefresh: (silent?: boolean) => void | Promise<void>;
}) {
  const [presets, setPresets] = useState<DnsPresetRow[]>([]);
  const [busy, setBusy] = useState(false);
  const [banner, setBanner] = useState<{ ok: boolean; text: string } | null>(null);
  const [cmdLogs, setCmdLogs] = useState<TerminalLogEntry[]>([]);
  const [customPri, setCustomPri] = useState("1.1.1.1");
  const [customSec, setCustomSec] = useState("1.0.0.1");

  const dns = health?.dns;

  useEffect(() => {
    void api("/api/dns/presets")
      .then((r) => (r.ok ? r.json() : null))
      .then((j) => {
        if (j?.items && Array.isArray(j.items)) setPresets(j.items);
      })
      .catch(() => {});
  }, []);

  const apply = async (preset: string) => {
    setBusy(true);
    setBanner(null);
    setCmdLogs([]);
    try {
      const body: Record<string, string> = { preset };
      if (preset === "custom") {
        body.primary = customPri.trim();
        if (customSec.trim()) body.secondary = customSec.trim();
      }
      const r = await api("/api/dns/apply", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const j = (await r.json()) as {
        ok?: boolean;
        error?: string;
        terminalLogs?: TerminalLogEntry[];
        elevated?: boolean;
      };
      const tl = Array.isArray(j.terminalLogs) ? j.terminalLogs : [];
      setCmdLogs(tl);
      if (!r.ok || !j.ok) {
        setBanner({ ok: false, text: j.error || `Request failed (${r.status})` });
        return;
      }
      setBanner({
        ok: true,
        text: j.elevated ? "DNS updated (administrator approval was used)." : "DNS updated.",
      });
      await onRefresh(true);
    } catch (e) {
      setBanner({ ok: false, text: String(e) });
    } finally {
      setBusy(false);
    }
  };

  const presetCards = presets.filter((p) => p.id !== "custom");

  return (
    <div className="card fade-in">
      <p className="hint card-intro">
        Switch IPv4 DNS for your active network (Wi‑Fi / Ethernet). <strong>Automatic</strong> uses your router /
        DHCP. On macOS and Windows, changing DNS may prompt for an administrator password. Linux uses{" "}
        <code>nmcli</code> (NetworkManager).
      </p>

      {dns && !dns.supported && (
        <div className="warning-banner" role="status">
          {dns.detail || "DNS control is not available on this system from this app."}
        </div>
      )}

      {dns && dns.supported && (
        <div className="dns-current-card">
          <p className="section-label">Current</p>
          <p className="dns-current-label">{dns.displayLabel}</p>
          {dns.service && (
            <p className="hint dns-current-hint">
              Interface / connection: <code>{dns.service}</code> · via {dns.method}
            </p>
          )}
          {!dns.automatic && dns.servers.length > 0 && (
            <p className="hint dns-current-hint">
              Servers: <code>{dns.servers.join(", ")}</code>
            </p>
          )}
          {dns.detail ? (
            <p className="hint dns-current-hint text-warn">{dns.detail}</p>
          ) : null}
        </div>
      )}

      {banner && <Banner ok={banner.ok}>{banner.text}</Banner>}

      <p className="section-label section-gap">Presets</p>
      <div className="dns-preset-grid">
        {presetCards.map((p) => (
          <button
            key={p.id}
            type="button"
            className={`scan-mode-card ${dns?.matchedPreset === p.id ? "selected" : ""}`}
            disabled={busy || !dns?.supported}
            title={p.servers ? p.servers.join(", ") : ""}
            onClick={() => void apply(p.id)}
          >
            <span className="scan-mode-icon"><Globe size={22} strokeWidth={1.8} aria-hidden /></span>
            <strong>{p.label}</strong>
            {p.servers && <span className="scan-mode-hint">{p.servers.join(" · ")}</span>}
          </button>
        ))}
      </div>

      <p className="section-label section-gap">Custom IPv4</p>
      <div className="dns-custom-row">
        <label className="dns-field">
          Primary
          <input
            type="text"
            value={customPri}
            onChange={(e) => setCustomPri(e.target.value)}
            placeholder="e.g. 1.1.1.1"
            spellCheck={false}
            disabled={busy}
          />
        </label>
        <label className="dns-field">
          Secondary (optional)
          <input
            type="text"
            value={customSec}
            onChange={(e) => setCustomSec(e.target.value)}
            placeholder="e.g. 1.0.0.1"
            spellCheck={false}
            disabled={busy}
          />
        </label>
        <button
          type="button"
          className="btn btn-primary dns-custom-apply"
          disabled={busy || !dns?.supported}
          onClick={() => void apply("custom")}
        >
          Apply custom
        </button>
      </div>

      <div className="dns-reset-row">
        <button
          type="button"
          className="btn btn-ghost"
          disabled={busy || !dns?.supported}
          onClick={() => void apply("automatic")}
        >
          <RotateCcw size={14} aria-hidden /> Reset to automatic (DHCP / router DNS)
        </button>
      </div>

      {busy && (
        <p className="hint dns-busy-hint">
          <span className="spinner-inline" aria-hidden />
          Applying…
        </p>
      )}

      <TerminalOutputPanel logs={cmdLogs} />
    </div>
  );
}
