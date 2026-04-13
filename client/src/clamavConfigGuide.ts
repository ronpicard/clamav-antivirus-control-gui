export type GuideField = {
  key: string;
  label: string;
  hint: string;
  options?: string[];
};

export const CLAMD_GUIDE_FIELDS: GuideField[] = [
  {
    key: "Foreground",
    label: "Run in foreground",
    hint: "If yes, clamd stays attached to the terminal. Usually no for a background service.",
    options: ["yes", "no"],
  },
  {
    key: "LogFile",
    label: "Log file path",
    hint: "Where clamd writes its log. Leave empty to use system default.",
    options: [
      "/var/log/clamav/clamd.log",
      "/opt/homebrew/var/log/clamav/clamd.log",
      "/usr/local/var/log/clamav/clamd.log",
    ],
  },
  {
    key: "LocalSocket",
    label: "Unix socket path",
    hint: "Socket clients use to talk to the daemon.",
    options: [
      "/opt/homebrew/var/run/clamav/clamd.sock",
      "/usr/local/var/run/clamav/clamd.sock",
      "/var/run/clamav/clamd.ctl",
      "/tmp/clamd.socket",
    ],
  },
  {
    key: "TCPSocket",
    label: "TCP port",
    hint: "If set, clamd listens on this TCP port. Use with care on networks.",
    options: ["3310"],
  },
  {
    key: "TCPAddr",
    label: "TCP bind address",
    hint: "Address for TCP socket — 127.0.0.1 limits to local connections.",
    options: ["127.0.0.1", "0.0.0.0", "localhost"],
  },
  {
    key: "MaxThreads",
    label: "Maximum worker threads",
    hint: "Parallel scan threads. Higher uses more CPU/RAM.",
    options: ["2", "4", "8", "12", "16"],
  },
  {
    key: "MaxDirectoryRecursion",
    label: "Max folder depth",
    hint: "How deep clamd recurses into subdirectories.",
    options: ["15", "20", "25", "0"],
  },
  {
    key: "ReadTimeout",
    label: "Read timeout (seconds)",
    hint: "How long to wait on slow clients before giving up.",
    options: ["120", "180", "300", "600"],
  },
  {
    key: "StreamMaxLength",
    label: "Max stream size",
    hint: "Upper limit for streamed data (M = megabytes).",
    options: ["25M", "50M", "100M", "200M", "500M"],
  },
  {
    key: "User",
    label: "Run as user",
    hint: "Unix user clamd drops privileges to after startup.",
    options: ["clamav", "_clamav", "root"],
  },
];

export const FRESHCLAM_GUIDE_FIELDS: GuideField[] = [
  {
    key: "Checks",
    label: "Check for updates (times per day)",
    hint: "How often freshclam looks for new signatures. 0 disables automatic checks.",
    options: ["1", "2", "6", "12", "24", "0"],
  },
  {
    key: "DatabaseMirror",
    label: "Database mirror host",
    hint: "Hostname of the ClamAV mirror.",
    options: ["database.clamav.net"],
  },
  {
    key: "DatabaseDirectory",
    label: "Virus database folder",
    hint: "Directory where .cvd / .cld signature files are stored.",
    options: [
      "/opt/homebrew/var/lib/clamav",
      "/usr/local/var/lib/clamav",
      "/var/lib/clamav",
    ],
  },
  {
    key: "LogTime",
    label: "Log timestamps",
    hint: "Prefix log lines with time.",
    options: ["yes", "no"],
  },
  {
    key: "LogFile",
    label: "freshclam log file",
    hint: "Path to freshclam log output.",
    options: [
      "/var/log/clamav/freshclam.log",
      "/opt/homebrew/var/log/clamav/freshclam.log",
      "/usr/local/var/log/clamav/freshclam.log",
    ],
  },
  {
    key: "MaxAttempts",
    label: "Max download attempts",
    hint: "Retries if a mirror download fails.",
    options: ["3", "5", "10"],
  },
  {
    key: "CompressLocalDatabase",
    label: "Compress local database",
    hint: "Save disk space after update.",
    options: ["yes", "no"],
  },
  {
    key: "DNSDatabaseInfo",
    label: "DNS TXT database info",
    hint: "Optional hostname for lightweight update checks via DNS.",
    options: ["current.cvd.clamav.net"],
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
