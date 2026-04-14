export {};

declare global {
  interface Window {
    clamavGUI?: {
      isElectron: boolean;
      getOpenAtLogin: () => Promise<boolean>;
      setOpenAtLogin: (open: boolean) => Promise<boolean>;
    };
  }
}
