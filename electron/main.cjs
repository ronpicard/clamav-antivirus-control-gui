const { app, BrowserWindow, dialog } = require("electron");
const path = require("path");
const fs = require("fs");
const { spawn } = require("child_process");

const GUI_PORT = process.env.CLAMAV_GUI_PORT || "38471";

function serverLogPath() {
  return path.join(app.getPath("userData"), "server.log");
}

function appendServerLog(chunk) {
  try {
    fs.appendFileSync(serverLogPath(), chunk);
  } catch {
    /* ignore */
  }
}

function projectRoot() {
  return path.join(__dirname, "..");
}

function resourcesRoot() {
  return app.isPackaged ? process.resourcesPath : projectRoot();
}

let serverProcess = null;

function startServer() {
  const root = resourcesRoot();
  const serverDir = path.join(root, "server");
  const serverEntry = path.join(serverDir, "index.js");
  const clientDist = path.join(root, "client", "dist");
  const scanRoot = path.join(app.getPath("documents"), "ClamAV-Scan");
  fs.mkdirSync(scanRoot, { recursive: true });

  if (!fs.existsSync(clientDist)) {
    throw new Error(
      `Web UI not found at ${clientDist}. Run: npm run build --prefix client`
    );
  }

  const env = {
    ...process.env,
    ELECTRON_RUN_AS_NODE: "1",
    PORT: GUI_PORT,
    BIND_HOST: "127.0.0.1",
    CLIENT_DIST: clientDist,
    SCAN_ROOT: scanRoot,
  };

  const logFile = serverLogPath();
  try {
    fs.writeFileSync(logFile, `--- start ${new Date().toISOString()}\n`);
  } catch {
    /* ignore */
  }

  serverProcess = spawn(process.execPath, [serverEntry], {
    cwd: serverDir,
    env,
    stdio: app.isPackaged ? ["ignore", "pipe", "pipe"] : "inherit",
  });

  if (app.isPackaged && serverProcess.stdout) {
    serverProcess.stdout.on("data", (d) => appendServerLog(String(d)));
  }
  if (app.isPackaged && serverProcess.stderr) {
    serverProcess.stderr.on("data", (d) => appendServerLog(String(d)));
  }

  serverProcess.on("error", (err) => {
    appendServerLog(`spawn error: ${err}\n`);
    console.error("ClamAV GUI server spawn failed:", err);
  });

  serverProcess.on("exit", (code) => {
    const line = `exit ${code}\n`;
    appendServerLog(line);
    if (code !== 0 && code !== null) {
      console.error("ClamAV GUI server exited with code", code);
    }
  });
}

async function waitForHealth(port) {
  const url = `http://127.0.0.1:${port}/api/health`;
  for (let i = 0; i < 100; i++) {
    try {
      const r = await fetch(url);
      if (r.ok) return;
    } catch {
      /* not ready */
    }
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error("The local ClamAV GUI server did not start in time.");
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1024,
    height: 800,
    minWidth: 720,
    minHeight: 520,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
    },
    show: true,
    backgroundColor: "#0f1419",
  });

  win.webContents.setWindowOpenHandler(() => ({ action: "deny" }));

  win.webContents.on("did-fail-load", (_e, code, desc, url) => {
    dialog.showErrorBox(
      "ClamAV Control — page failed to load",
      `Could not load the app UI (${code}: ${desc}).\n\nURL: ${url}\n\nIf the local server exited, check:\n${serverLogPath()}`
    );
    win.show();
  });

  return win.loadURL(`http://127.0.0.1:${GUI_PORT}/`);
}

function stopServer() {
  if (serverProcess && !serverProcess.killed) {
    if (process.platform === "win32") {
      serverProcess.kill();
    } else {
      serverProcess.kill("SIGTERM");
    }
    serverProcess = null;
  }
}

app.whenReady().then(async () => {
  try {
    startServer();
    await waitForHealth(GUI_PORT);
    await createWindow();
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error(e);
    dialog.showErrorBox(
      "ClamAV Control — could not start",
      `${msg}\n\nDetails may be in:\n${serverLogPath()}`
    );
    stopServer();
    app.quit();
  }
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    stopServer();
    app.quit();
  }
});

app.on("before-quit", () => {
  stopServer();
});

app.on("activate", async () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    try {
      if (!serverProcess || serverProcess.killed) {
        startServer();
      }
      await waitForHealth(GUI_PORT);
      await createWindow();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error(e);
      dialog.showErrorBox("ClamAV Control — could not open window", `${msg}\n\n${serverLogPath()}`);
    }
  }
});
