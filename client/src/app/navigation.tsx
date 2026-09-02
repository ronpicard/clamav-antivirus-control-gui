import {
  Activity,
  CalendarClock,
  CircleHelp,
  Globe,
  LayoutDashboard,
  LockKeyhole,
  PackageOpen,
  ScanLine,
  Settings2,
  ShieldCheck,
  SlidersHorizontal,
  type LucideIcon,
} from "lucide-react";

export const NAV_ITEMS = [
  { id: "home", label: "Status", group: "Protection", icon: LayoutDashboard, title: "Your protection at a glance" },
  { id: "scan", label: "Scan", group: "Protection", icon: ScanLine, title: "Scan files with live progress" },
  { id: "realtime", label: "Real-time", group: "Protection", icon: Activity, title: "Monitor files in real time" },
  { id: "quarantine", label: "Quarantine", group: "Protection", icon: LockKeyhole, title: "View and manage quarantined threats" },
  { id: "auto-install", label: "Setup", group: "Advanced", icon: PackageOpen, title: "Install ClamAV — guided on Mac + Homebrew" },
  { id: "cron", label: "Schedules", group: "Advanced", icon: CalendarClock, title: "Automate updates and scans (Mac/Linux)" },
  { id: "config", label: "Engine config", group: "Advanced", icon: Settings2, title: "Edit clamd and freshclam settings" },
  { id: "dns", label: "DNS", group: "Advanced", icon: Globe, title: "DNS resolver: OpenDNS, Google, Cloudflare, DHCP, custom" },
  { id: "settings", label: "Settings", group: "General", icon: SlidersHorizontal, title: "App preferences" },
  { id: "instructions", label: "Help", group: "General", icon: CircleHelp, title: "Install ClamAV and use this app" },
] as const;

export type TabId = (typeof NAV_ITEMS)[number]["id"];

const NAV_GROUPS = ["Protection", "Advanced", "General"] as const;

function NavigationItem({
  id,
  label,
  icon: Icon,
  active,
  onSelect,
}: {
  id: TabId;
  label: string;
  icon: LucideIcon;
  active: boolean;
  onSelect: (id: TabId) => void;
}) {
  return (
    <button
      type="button"
      className={`nav-item ${active ? "active" : ""}`}
      onClick={() => onSelect(id)}
      aria-current={active ? "page" : undefined}
    >
      <Icon size={17} strokeWidth={1.8} aria-hidden />
      <span>{label}</span>
    </button>
  );
}

export function AppNavigation({
  activeTab,
  protectionReady,
  statusDetail,
  loading,
  onSelect,
}: {
  activeTab: TabId;
  protectionReady: boolean;
  statusDetail?: string | null;
  loading: boolean;
  onSelect: (id: TabId) => void;
}) {
  return (
    <aside className="sidebar">
      <div className="brand-row">
        <div className="brand-icon" aria-hidden>
          <ShieldCheck size={22} strokeWidth={1.9} />
        </div>
        <div>
          <div className="brand-name">
            ClamAV Control
            <span className="brand-version" title={`Version ${__APP_VERSION__}`}>
              v{__APP_VERSION__}
            </span>
          </div>
          <div className="brand-caption">Local antivirus</div>
        </div>
      </div>
      <nav className="sidebar-nav" aria-label="Main sections">
        {NAV_GROUPS.map((group) => (
          <div className="nav-group" key={group}>
            <div className="nav-group-label">{group}</div>
            {NAV_ITEMS.filter((item) => item.group === group).map((item) => (
              <NavigationItem
                key={item.id}
                id={item.id}
                label={item.label}
                icon={item.icon}
                active={activeTab === item.id}
                onSelect={onSelect}
              />
            ))}
          </div>
        ))}
      </nav>
      <button
        type="button"
        className="sidebar-status"
        title="Open the Status page"
        onClick={() => onSelect("home")}
      >
        <span className={`sidebar-status-dot ${loading ? "" : protectionReady ? "ok" : "attention"}`} aria-hidden />
        <div>
          <strong>{loading ? "Checking status" : protectionReady ? "You're protected" : "Needs attention"}</strong>
          <span>
            {loading
              ? "Looking at this device…"
              : protectionReady
                ? "All protection is active"
                : statusDetail || "Open Status to see details"}
          </span>
        </div>
      </button>
    </aside>
  );
}
