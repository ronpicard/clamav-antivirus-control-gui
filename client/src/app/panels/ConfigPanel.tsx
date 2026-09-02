import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import { applyGuidedValues, guideFieldsFor, parseGuidedValues, type GuideField } from "../../clamavConfigGuide";

const CUSTOM_SENTINEL = "__custom__";
const EMPTY_SENTINEL = "__empty__";

function GuidedFieldInput({
  field,
  value,
  onChange,
}: {
  field: GuideField;
  value: string;
  onChange: (v: string) => void;
}) {
  const opts = field.options ?? [];
  const hasOptions = opts.length > 0;
  const isPreset = hasOptions && opts.includes(value);
  const isCustom = !isPreset && value !== "";
  const [customMode, setCustomMode] = useState(isCustom);

  useEffect(() => {
    if (value === "" || opts.includes(value)) {
      setCustomMode(false);
    } else if (value !== "") {
      setCustomMode(true);
    }
  }, [value, opts]);

  if (!hasOptions) {
    return (
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={`${field.key} …`}
        spellCheck={false}
      />
    );
  }

  const handleSelect = (v: string) => {
    if (v === CUSTOM_SENTINEL) {
      setCustomMode(true);
      return;
    }
    if (v === EMPTY_SENTINEL) {
      onChange("");
      setCustomMode(false);
      return;
    }
    onChange(v);
    setCustomMode(false);
  };

  const selectValue = customMode ? CUSTOM_SENTINEL : value === "" ? EMPTY_SENTINEL : value;

  return (
    <div className="guided-input-combo">
      <select
        value={selectValue}
        onChange={(e) => handleSelect(e.target.value)}
        className="guided-select"
      >
        <option value={EMPTY_SENTINEL}>— not set —</option>
        {opts.map((o) => (
          <option key={o} value={o}>
            {o}
          </option>
        ))}
        <option value={CUSTOM_SENTINEL}>Custom…</option>
      </select>
      {customMode && (
        <input
          type="text"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder="Enter custom value…"
          spellCheck={false}
          className="guided-custom-input"
          autoFocus
        />
      )}
    </div>
  );
}

export function ConfigPanel() {
  const [which, setWhich] = useState<"clamd" | "freshclam">("clamd");
  const [content, setContent] = useState("");
  const [guidedValues, setGuidedValues] = useState<Record<string, string>>({});
  const [editorMode, setEditorMode] = useState<"guided" | "raw">("guided");
  const [msg, setMsg] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const fields = guideFieldsFor(which);

  const load = useCallback(async () => {
    setLoading(true);
    setMsg(null);
    try {
      const r = await api(`/api/config/${which}`);
      if (!r.ok) throw new Error(await r.text());
      const j = await r.json();
      setContent(j.content);
      setGuidedValues(parseGuidedValues(j.content, guideFieldsFor(which)));
    } catch (e) {
      setMsg(String(e));
    } finally {
      setLoading(false);
    }
  }, [which]);

  useEffect(() => {
    load();
  }, [load]);

  const mergeGuidedIntoContent = () => applyGuidedValues(content, fields, guidedValues);

  const switchToRaw = () => {
    if (editorMode === "guided") {
      setContent(mergeGuidedIntoContent());
    }
    setEditorMode("raw");
  };

  const switchToGuided = () => {
    setGuidedValues(parseGuidedValues(content, fields));
    setEditorMode("guided");
  };

  const save = async () => {
    setLoading(true);
    setMsg(null);
    const bodyContent = editorMode === "guided" ? mergeGuidedIntoContent() : content;
    try {
      const r = await api(`/api/config/${which}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content: bodyContent }),
      });
      if (!r.ok) throw new Error(await r.text());
      setContent(bodyContent);
      setGuidedValues(parseGuidedValues(bodyContent, fields));
      setMsg("Saved. Restart the daemon from the Dashboard to apply changes.");
    } catch (e) {
      setMsg(String(e));
    } finally {
      setLoading(false);
    }
  };

  const resetToDefaults = async () => {
    if (
      !window.confirm(
        "Reset both config files to defaults? .bak backups are created automatically.",
      )
    ) {
      return;
    }
    setLoading(true);
    setMsg(null);
    try {
      const r = await api("/api/config/reset", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ which: "both" }),
      });
      if (!r.ok) throw new Error(await r.text());
      await load();
      setEditorMode("raw");
      setMsg("Reset complete. Review paths, then restart the daemon.");
    } catch (e) {
      setMsg(String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card fade-in">
      <p className="hint card-intro">
        Edit ClamAV settings. Each save creates a <code>.bak</code> backup.
      </p>

      <div className="segmented" role="tablist" aria-label="Config file">
        <button
          type="button"
          role="tab"
          aria-selected={which === "clamd"}
          className={which === "clamd" ? "active" : ""}
          onClick={() => setWhich("clamd")}
        >
          clamd.conf
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={which === "freshclam"}
          className={which === "freshclam" ? "active" : ""}
          onClick={() => setWhich("freshclam")}
        >
          freshclam.conf
        </button>
      </div>

      <div className="segmented segmented-stack" role="tablist" aria-label="Editor mode">
        <button
          type="button"
          role="tab"
          aria-selected={editorMode === "guided"}
          className={editorMode === "guided" ? "active" : ""}
          onClick={switchToGuided}
        >
          Guided
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={editorMode === "raw"}
          className={editorMode === "raw" ? "active" : ""}
          onClick={switchToRaw}
        >
          Raw file
        </button>
      </div>

      <div className="row config-actions">
        <button type="button" className="btn btn-ghost" onClick={load} disabled={loading}>
          {loading ? (
            <>
              <span className="spinner-inline" aria-hidden />
              Loading…
            </>
          ) : (
            "Reload from disk"
          )}
        </button>
        <button type="button" className="btn btn-primary" onClick={save} disabled={loading}>
          Save changes
        </button>
        {editorMode === "raw" && (
          <button type="button" className="btn btn-danger" onClick={resetToDefaults} disabled={loading}>
            Reset files to default
          </button>
        )}
      </div>

      {editorMode === "guided" ? (
        <>
          <p className="guided-footnote">
            Showing frequently edited directives. Other settings remain in the file and appear in Raw mode.
          </p>
          <div className="guided-stack">
            {fields.map((f) => (
              <div key={f.key} className="guided-field">
                <label>{f.label}</label>
                <p className="field-hint-text">{f.hint}</p>
                <GuidedFieldInput
                  field={f}
                  value={guidedValues[f.key] ?? ""}
                  onChange={(v) => setGuidedValues((prev) => ({ ...prev, [f.key]: v }))}
                />
              </div>
            ))}
          </div>
        </>
      ) : (
        <>
          <label htmlFor="cfg">Full file (exactly as on disk after merge)</label>
          <textarea id="cfg" value={content} onChange={(e) => setContent(e.target.value)} spellCheck={false} />
        </>
      )}
      {msg && <p className="hint">{msg}</p>}
    </div>
  );
}
