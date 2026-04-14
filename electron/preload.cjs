const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("clamavGUI", {
  isElectron: true,
  getOpenAtLogin: () => ipcRenderer.invoke("clamav:get-open-at-login"),
  setOpenAtLogin: (open) => ipcRenderer.invoke("clamav:set-open-at-login", open),
});
