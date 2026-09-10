/**
 * preload.cjs — Electron Preload Script for Rakshak 2.0
 *
 * Exposes a secure bridge between the web dashboard and native OS desktop APIs.
 */
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  isDesktopApp: true,
  platform: process.platform,

  // Native desktop notification
  showNotification: (payload) => ipcRenderer.invoke('show-notification', payload),

  // Open external link in default OS browser
  openExternal: (url) => ipcRenderer.invoke('open-external', url),

  // Check agent & backend health
  getAppVersion: () => ipcRenderer.invoke('get-app-version'),
});
