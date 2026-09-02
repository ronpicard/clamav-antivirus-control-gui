export function InstructionsPanel() {
  return (
    <div className="card fade-in">
      <p className="hint card-intro">
        ClamAV Control is a GUI for the open-source ClamAV antivirus engine.
        It manages scanning, definitions, quarantine, and scheduling from one place.
      </p>

      <details className="help-section" open>
        <summary>Getting started</summary>
        <div className="help-body">
          <ol className="instructions-steps">
            <li><strong>Install ClamAV</strong> — use the Auto-install tab (macOS / Homebrew) or your OS package manager.</li>
            <li><strong>Check the Dashboard</strong> — all indicators should be green.</li>
            <li><strong>Update definitions</strong> — click “Update definitions” to fetch the latest signatures.</li>
            <li><strong>Run a scan</strong> — go to Scan, pick Standard / Full / Custom, and start.</li>
          </ol>
        </div>
      </details>

      <details className="help-section">
        <summary>Install by operating system</summary>
        <div className="help-body">
          <div className="instructions-os">
            <section>
              <h3>macOS</h3>
              <p>Use the <strong>Auto-install</strong> tab or manually: <code>brew install clamav</code> then <code>brew services start clamav</code>.</p>
            </section>
            <section>
              <h3>Windows</h3>
              <p>Download the installer from <a href="https://www.clamav.net/downloads" target="_blank" rel="noreferrer">clamav.net</a>. Use the Dashboard to start the daemon.</p>
            </section>
            <section>
              <h3>Linux</h3>
              <p><code>apt install clamav clamav-daemon</code> or equivalent. Real-time scanning via <code>clamonacc</code> may be available.</p>
            </section>
          </div>
        </div>
      </details>

      <details className="help-section">
        <summary>App tabs explained</summary>
        <div className="help-body">
          <dl className="tab-explainer">
            <dt>Dashboard</dt><dd>Status overview. Start/stop daemon, update definitions, toggle firewall.</dd>
            <dt>Auto-install</dt><dd>One-click install/uninstall on macOS. Manual commands for other platforms.</dd>
            <dt>Scan</dt><dd>Standard, Full, or Custom scan with live file log. Threats are auto-quarantined.</dd>
            <dt>Quarantine</dt><dd>Review, restore, or delete quarantined files.</dd>
            <dt>Schedules</dt><dd>Cron jobs for automatic updates and scans (macOS/Linux).</dd>
            <dt>Config</dt><dd>Edit ClamAV config files in Guided or Raw mode.</dd>
            <dt>DNS</dt><dd>Optional resolver presets (OpenDNS, Google, Cloudflare, DHCP, custom) for the active network.</dd>
            <dt>Settings</dt><dd>Refresh status, auto-start real-time monitoring, optional daemon/cron setup on app open, open-at-login (desktop).</dd>
          </dl>
        </div>
      </details>

      <details className="help-section">
        <summary>Passwords &amp; privileges</summary>
        <div className="help-body">
          <p>Commands run as your user first. On permission error, the app retries with elevation:</p>
          <ul>
            <li><strong>macOS</strong> — admin password dialog (never <code>sudo brew</code>).</li>
            <li><strong>Linux</strong> — <code>pkexec</code> prompt.</li>
            <li><strong>Windows</strong> — UAC elevation.</li>
          </ul>
        </div>
      </details>

      <details className="help-section">
        <summary>Official resources</summary>
        <div className="help-body">
          <ul className="instructions-links">
            <li><a href="https://www.clamav.net/downloads" target="_blank" rel="noreferrer">ClamAV downloads</a></li>
            <li><a href="https://docs.clamav.net/" target="_blank" rel="noreferrer">ClamAV documentation</a></li>
          </ul>
        </div>
      </details>
    </div>
  );
}
