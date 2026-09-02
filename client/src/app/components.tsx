import type { ReactNode } from "react";
import { Check, X, type LucideIcon } from "lucide-react";
import type { TerminalLogEntry } from "./types";

export function Banner({
  ok,
  children,
  role = "status",
  className = "",
}: {
  ok: boolean;
  children: ReactNode;
  role?: "status" | "alert";
  className?: string;
}) {
  const Icon = ok ? Check : X;
  return (
    <div className={`action-banner fade-in ${ok ? "ok" : "err"} ${className}`} role={role}>
      <Icon size={14} strokeWidth={2.5} className="action-banner-icon" aria-hidden />
      <span>{children}</span>
    </div>
  );
}

export function Toggle({
  checked,
  disabled,
  onChange,
  label,
}: {
  checked: boolean;
  disabled?: boolean;
  onChange: (checked: boolean) => void;
  label: string;
}) {
  return (
    <label className={`switch ${disabled ? "switch-disabled" : ""}`}>
      <input
        type="checkbox"
        role="switch"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span className="switch-track" aria-hidden>
        <span className="switch-thumb" />
      </span>
      <span className="switch-label">{label}</span>
    </label>
  );
}

export function EmptyState({
  icon: Icon,
  title,
  children,
}: {
  icon: LucideIcon;
  title: string;
  children?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <Icon size={28} strokeWidth={1.5} aria-hidden />
      <strong>{title}</strong>
      {children && <span>{children}</span>}
    </div>
  );
}

export function TerminalOutputPanel({ logs }: { logs: TerminalLogEntry[] }) {
  if (!logs.length) return null;
  return (
    <div className="terminal-output-panel">
      <p className="section-label">Terminal output (commands run)</p>
      <div className="terminal-output-list">
        {logs.map((log, i) => {
          const cmdline =
            log.argv && log.argv.length > 0
              ? log.argv.map((a) => (/\s/.test(a) ? JSON.stringify(a) : a)).join(" ")
              : log.label || "—";
          return (
            <details key={i} className="terminal-log-block" open={i >= logs.length - 2}>
              <summary className="terminal-log-summary">
                <span className={`terminal-exit-pill ${log.ok ? "ok" : "bad"}`}>
                  exit {typeof log.code === "number" ? log.code : "—"}
                </span>
                <code className="terminal-cmd-line">{cmdline}</code>
                {log.label && log.argv?.length ? <span className="terminal-log-note"> — {log.label}</span> : null}
                {log.via ? <span className="terminal-log-note"> ({log.via})</span> : null}
              </summary>
              <div className="terminal-streams">
                {log.stderr ? (
                  <div className="terminal-stream">
                    <span className="term-stream-label">stderr</span>
                    <pre className="terminal-pre">{log.stderr}</pre>
                  </div>
                ) : null}
                {log.stdout ? (
                  <div className="terminal-stream">
                    <span className="term-stream-label">stdout</span>
                    <pre className="terminal-pre">{log.stdout}</pre>
                  </div>
                ) : null}
                {!log.stderr && !log.stdout ? (
                  <p className="hint terminal-empty-note">(no stdout/stderr captured)</p>
                ) : null}
              </div>
            </details>
          );
        })}
      </div>
    </div>
  );
}
