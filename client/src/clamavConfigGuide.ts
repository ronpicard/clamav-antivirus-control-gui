export type GuideField = {
  key: string;
  label: string;
  hint: string;
};

/** Common clamd.conf directives — rest of file stays in Raw mode */
export const CLAMD_GUIDE_FIELDS: GuideField[] = [
  {
    key: "Foreground",
    label: "Run in foreground",
    hint: "yes/no — if yes, clamd stays attached to the terminal (typical for debugging). Usually no for a background service.",
  },
  {
    key: "LogFile",
    label: "Log file path",
    hint: "Where clamd writes its log. Leave empty to remove the line (use system default if your install provides one).",
  },
  {
    key: "LocalSocket",
    label: "Unix socket path",
    hint: "Socket clients like clamdscan use to talk to the daemon (common on Linux/macOS).",
  },
  {
    key: "TCPSocket",
    label: "TCP port",
    hint: "If set, clamd listens on this TCP port (often 3310). Use with care on networks.",
  },
  {
    key: "TCPAddr",
    label: "TCP bind address",
    hint: "Address for TCP socket — often 127.0.0.1 so only local apps can connect.",
  },
  {
    key: "MaxThreads",
    label: "Maximum worker threads",
    hint: "Parallel scan threads. Higher uses more CPU/RAM.",
  },
  {
    key: "MaxDirectoryRecursion",
    label: "Max folder depth",
    hint: "How deep clamd recurses into subdirectories (number).",
  },
  {
    key: "ReadTimeout",
    label: "Read timeout (seconds)",
    hint: "How long to wait on slow clients before giving up.",
  },
  {
    key: "StreamMaxLength",
    label: "Max stream size",
    hint: "Upper limit for streamed data (size suffix like M for megabytes).",
  },
  {
    key: "User",
    label: "Run as user",
    hint: "Unix user clamd drops privileges to after startup.",
  },
];

export const FRESHCLAM_GUIDE_FIELDS: GuideField[] = [
  {
    key: "Checks",
    label: "Check for updates (times per day)",
    hint: "How often freshclam looks for new signatures (0 disables automatic checks in many setups).",
  },
  {
    key: "DatabaseMirror",
    label: "Database mirror host",
    hint: "Hostname of the ClamAV mirror (e.g. database.clamav.net).",
  },
  {
    key: "DatabaseDirectory",
    label: "Virus database folder",
    hint: "Directory where .cvd / .cld signature files are stored.",
  },
  {
    key: "LogTime",
    label: "Log timestamps",
    hint: "yes/no — prefix log lines with time.",
  },
  {
    key: "LogFile",
    label: "freshclam log file",
    hint: "Path to freshclam log output.",
  },
  {
    key: "MaxAttempts",
    label: "Max download attempts",
    hint: "Retries if a mirror download fails.",
  },
  {
    key: "CompressLocalDatabase",
    label: "Compress local database",
    hint: "yes/no — save disk space after update.",
  },
  {
    key: "DNSDatabaseInfo",
    label: "DNS TXT database info",
    hint: "Optional hostname for lightweight update checks via DNS.",
  },
];

export function guideFieldsFor(which: "clamd" | "freshclam"): GuideField[] {
  return which === "freshclam" ? FRESHCLAM_GUIDE_FIELDS : CLAMD_GUIDE_FIELDS;
}

export function parseGuidedValues(raw: string, fields: GuideField[]): Record<string, string> {
  const want = new Set(fields.map((f) => f.key));
  const out: Record<string, string> = {};
  for (const line of raw.split("\n")) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const m = /^(\S+)\s+(.*)$/.exec(t);
    if (!m) continue;
    const k = m[1];
    if (want.has(k) && out[k] === undefined) {
      out[k] = m[2].trim();
    }
  }
  for (const f of fields) {
    if (out[f.key] === undefined) out[f.key] = "";
  }
  return out;
}

export function setDirectiveLine(raw: string, key: string, value: string): string {
  const lines = raw.split("\n");
  const filtered = lines.filter((line) => {
    const t = line.trim();
    if (!t || t.startsWith("#")) return true;
    const first = t.split(/\s+/)[0];
    return first !== key;
  });
  let body = filtered.join("\n").replace(/\s+$/, "");
  const v = value.trim();
  if (v !== "") {
    body += (body ? "\n" : "") + `${key} ${v}`;
  }
  return body ? `${body}\n` : "";
}

export function applyGuidedValues(
  raw: string,
  fields: GuideField[],
  values: Record<string, string>
): string {
  let out = raw;
  for (const f of fields) {
    const v = values[f.key] ?? "";
    out = setDirectiveLine(out, f.key, v);
  }
  return out;
}
