import type { Health } from "./types";

export type ProtectionProblem = {
  id: "install" | "realtime" | "firewall";
  text: string;
  short: string;
};

/** Single source of truth for "is this device protected?" — used by the
 *  Status hero and the sidebar badge so they can never disagree.
 *
 *  The clamd daemon is deliberately not a problem here: the Scan tab and
 *  real-time protection run standalone `clamscan`, so a stopped daemon only
 *  affects scheduled (cron) scans, which call `clamdscan`. */
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
