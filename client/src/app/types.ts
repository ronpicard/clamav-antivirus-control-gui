export type RtEvent = {
  file: string | null;
  status: "clean" | "threat" | "error" | "scanning" | "info";
  detail: string | null;
  ts: number;
};

export type Health = {
  ok: boolean;
  clamav: {
    clamdscanInstalled: boolean;
    freshclamInstalled: boolean;
    daemonResponding: boolean;
    pingMethod?: string | null;
    pingError?: string | null;
  };
  firewall?: { active: boolean | null; source: string; detail: string };
  dns?: {
    supported: boolean;
    ok: boolean;
    platform?: string;
    method?: string;
    service?: string | null;
    servers: string[];
    automatic?: boolean;
    matchedPreset?: string;
    displayLabel: string;
    detail?: string;
  };
  clamdService?: {
    running: boolean;
    unit: string | null;
    method: string;
    socketOk: boolean;
  };
  realtimeMonitor?: {
    running: boolean;
    method: string | null;
    watchedDirs: string[];
    filesScanned: number;
    threatsFound: number;
    lastEvent: RtEvent | null;
    startedAt: number | null;
    error: string | null;
  };
  paths: {
    clamdConf: string;
    freshclamConf: string;
    scanRoot: string;
    clamdUnixSocket?: string | null;
    clamdTcp?: string | null;
  };
  scan?: {
    quickDirs: string[];
    fullPath: string;
    customHint: string;
  };
  quarantine?: {
    dir: string;
    enabled: boolean;
  };
};

export type InstallStatus = {
  ok: boolean;
  platform: string;
  canAutomate: boolean;
  brew: { path: string | null; version: string | null; clamavInstalled: boolean };
  paths: {
    homebrewPrefix: string | null;
    clamdConf: string;
    confExists: boolean;
    listenerConfigured: boolean;
  };
  binaries: { clamdscanOk: boolean; freshclamOk: boolean };
  manualSteps: { title: string; command: string }[];
  uninstall?: {
    canAutomated: boolean;
    manualSteps: { title: string; command: string }[];
  };
};

export type CronJob = { id: number; line: string; lineIndex: number };

export type TerminalLogEntry = {
  label?: string;
  argv?: string[];
  stdout?: string;
  stderr?: string;
  code?: number;
  ok?: boolean;
  via?: string;
  elevated?: boolean;
  brewUsedAdminRetry?: boolean;
};

export type QuarantineItem = {
  name: string;
  path: string;
  size: number;
  quarantinedAt: number;
};

export type ScanMode = "quick" | "full" | "custom";

export type ScanLine = {
  file: string | null;
  status: "ok" | "found" | "skip" | "info";
  detail: string | null;
};

export type ScanStreamState = {
  type?: string;
  status: string;
  mode?: string;
  targetLabel?: string;
  targetPath?: string;
  filesScanned: number;
  totalFiles: number | null;
  countPartial: boolean;
  progress: number;
  progressExact: boolean;
  etaSeconds?: number | null;
  etaConfidence?: string;
  filesPerSecond?: number | null;
  currentFile: string;
  infectedCount: number;
  scanLines?: ScanLine[];
  stdoutTail?: string;
  exitCode?: number | null;
  exitSignal?: string | null;
  spawnError?: string | null;
  findings?: string[];
};

export type ScanHistoryEntry = {
  id: string;
  endedAt: number;
  mode: string;
  targetLabel: string;
  status: string;
  infectedCount: number;
};

export type ScanSessionState = {
  activeScanId: string | null;
  live: ScanStreamState | null;
  scanErr: string | null;
  pendingStart: boolean;
};

export const EMPTY_SCAN_SESSION: ScanSessionState = {
  activeScanId: null,
  live: null,
  scanErr: null,
  pendingStart: false,
};
