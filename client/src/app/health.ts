import type { Health } from "./types";

export type ProtectionProblem = {
  id: "install" | "engine" | "realtime" | "firewall";
  text: string;
  short: string;
};

/** Single source of truth for "is this device protected?" — used by the
 *  Status hero and the sidebar badge so they can never disagree. */
export function protectionProblems(health: Health | null): ProtectionProblem[] {
  if (!health) return [];
  const c = health.clamav;
  const installed = !!c?.freshclamInstalled && !!c?.clamdscanInstalled;
  const problems: ProtectionProblem[] = [];
  if (!installed) {
    problems.push({
      id: "install",
      text: "ClamAV is not installed on this computer.",
      short: "ClamAV is not installed",
    });
  } else if (!c.daemonResponding) {
    problems.push({
      id: "engine",
      text: "The scanner engine is not running.",
      short: "Scanner engine is off",
    });
  }
  if (installed && !health.realtimeMonitor?.running) {
    problems.push({
      id: "realtime",
      text: "Real-time protection is turned off.",
      short: "Real-time protection is off",
    });
  }
  if (health.firewall?.active === false) {
    problems.push({
      id: "firewall",
      text: "The system firewall is turned off.",
      short: "Firewall is off",
    });
  }
  return problems;
}
