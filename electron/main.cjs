/**
 * main.cjs — Electron Main Process for Rakshak 2.0 Desktop Application
 *
 * Provides native desktop window management, macOS/Linux titlebars,
 * system tray status, native OS notifications, and service orchestration.
 */
const { app, BrowserWindow, Tray, Menu, Notification, shell, ipcMain, nativeImage } = require('electron');
const path = require('path');

let mainWindow = null;
let tray = null;
let isQuitting = false;

const DASHBOARD_URL = process.env.CLIENT_URL || 'http://localhost:5180';
const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:5050';

const loadingHtml = `
  <!DOCTYPE html>
  <html>
    <head>
      <meta charset="utf-8">
      <title>Starting Rakshak 2.0...</title>
      <style>
        body {
          margin: 0;
          background: #050b14;
          color: #e2e8f0;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          display: flex;
          align-items: center;
          justify-content: center;
          height: 100vh;
          flex-direction: column;
          gap: 16px;
          user-select: none;
        }
        .spinner {
          width: 44px;
          height: 44px;
          border: 3px solid rgba(0, 212, 255, 0.15);
          border-top-color: #00d4ff;
          border-radius: 50%;
          animation: spin 0.9s linear infinite;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        h2 { margin: 0; font-size: 16px; font-weight: 600; color: #f8fafc; }
        p { margin: 0; font-size: 12px; color: #64748b; }
      </style>
    </head>
    <body>
      <div class="spinner"></div>
      <h2>Starting Rakshak SOC Desktop...</h2>
      <p>Connecting to local telemetry engine at ${DASHBOARD_URL}...</p>
    </body>
  </html>
`;

function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1080,
    minHeight: 720,
    title: 'Rakshak 2.0 — Live SOC Operations',
    backgroundColor: '#050b14',
    show: false,
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
    trafficLightPosition: { x: 18, y: 18 },
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: false,
    },
  });

  // Log renderer console events to main process stdout for debugging
  mainWindow.webContents.on('console-message', (e, level, msg, line, src) => {
    if (level >= 2) {
      console.log(`[Renderer Log] ${msg} (${path.basename(src || '')}:${line})`);
    }
  });

  // Handle external links securely
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });

  // Enable native right-click context menu (Cut, Copy, Paste, Select All)
  mainWindow.webContents.on('context-menu', (event, params) => {
    const contextTemplate = [];
    if (params.isEditable) {
      contextTemplate.push(
        { role: 'undo' },
        { role: 'redo' },
        { type: 'separator' },
        { role: 'cut' },
        { role: 'copy' },
        { role: 'paste' },
        { type: 'separator' },
        { role: 'selectAll' }
      );
    } else if (params.selectionText) {
      contextTemplate.push(
        { role: 'copy' },
        { role: 'selectAll' }
      );
    }
    if (contextTemplate.length > 0) {
      Menu.buildFromTemplate(contextTemplate).popup();
    }
  });

  // Window show when ready or fallback
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  // Fallback to show window after 800ms if ready-to-show is delayed
  setTimeout(() => {
    if (mainWindow && !mainWindow.isVisible()) {
      mainWindow.show();
    }
  }, 800);

  // Load dashboard with graceful retry
  loadDashboard();

  mainWindow.on('close', (event) => {
    if (!isQuitting && process.platform === 'darwin') {
      event.preventDefault();
      mainWindow.hide();
    }
  });
}

// Robust connection loader: tries loading immediately, retries gracefully if server is booting
async function loadDashboard() {
  if (!mainWindow || mainWindow.isDestroyed()) return;

  try {
    await mainWindow.loadURL(DASHBOARD_URL);
    console.log(`[Rakshak Desktop] Connected successfully to ${DASHBOARD_URL}`);
  } catch (err) {
    console.log(`[Rakshak Desktop] Waiting for ${DASHBOARD_URL} to become ready...`);
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(loadingHtml)}`).catch(() => {});
      setTimeout(loadDashboard, 1500);
    }
  }
}

function createTray() {
  try {
    const icon = nativeImage.createFromBuffer(
      Buffer.from(
        'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAElJREFUOE9jZKAQMFKon2HUAAYGBoa/DAwM/5HVMDIy/kdzH7IaXJqQDSBnECX+I2sGMg0mN1DkBmoYBqgXJ4NmoGAYDAA+2QgZt80U+gAAAABJRU5ErkJggg==',
        'base64'
      )
    );

    tray = new Tray(icon);
    tray.setToolTip('Rakshak 2.0 Live SOC');

    const contextMenu = Menu.buildFromTemplate([
      {
        label: 'Open Rakshak SOC',
        click: () => {
          if (mainWindow) {
            mainWindow.show();
            mainWindow.focus();
          }
        },
      },
      { type: 'separator' },
      {
        label: 'Open in Browser',
        click: () => shell.openExternal(DASHBOARD_URL),
      },
      { type: 'separator' },
      {
        label: 'Quit Rakshak',
        click: () => {
          isQuitting = true;
          app.quit();
        },
      },
    ]);

    tray.setContextMenu(contextMenu);
    tray.on('click', () => {
      if (mainWindow) {
        if (mainWindow.isVisible()) {
          mainWindow.hide();
        } else {
          mainWindow.show();
          mainWindow.focus();
        }
      }
    });
  } catch (trayErr) {
    console.warn('[Rakshak Desktop] Tray skipped:', trayErr.message);
  }
}

function setupApplicationMenu() {
  const isMac = process.platform === 'darwin';
  const template = [
    ...(isMac ? [{
      label: 'Rakshak',
      submenu: [
        { role: 'about' },
        { type: 'separator' },
        { role: 'services' },
        { type: 'separator' },
        { role: 'hide' },
        { role: 'hideOthers' },
        { role: 'unhide' },
        { type: 'separator' },
        {
          label: 'Quit Rakshak',
          accelerator: 'Command+Q',
          click: () => {
            isQuitting = true;
            app.quit();
          },
        },
      ],
    }] : []),
    {
      label: 'Edit',
      submenu: [
        { role: 'undo' },
        { role: 'redo' },
        { type: 'separator' },
        { role: 'cut' },
        { role: 'copy' },
        { role: 'paste' },
        ...(isMac ? [
          { role: 'pasteAndMatchStyle' },
          { role: 'delete' },
          { role: 'selectAll' },
        ] : [
          { role: 'delete' },
          { type: 'separator' },
          { role: 'selectAll' },
        ]),
      ],
    },
    {
      label: 'View',
      submenu: [
        { role: 'reload' },
        { role: 'forceReload' },
        { role: 'toggleDevTools' },
        { type: 'separator' },
        { role: 'resetZoom' },
        { role: 'zoomIn' },
        { role: 'zoomOut' },
        { type: 'separator' },
        { role: 'togglefullscreen' },
      ],
    },
    {
      label: 'Window',
      submenu: [
        { role: 'minimize' },
        { role: 'zoom' },
        ...(isMac ? [
          { type: 'separator' },
          { role: 'front' },
        ] : [
          { role: 'close' },
        ]),
      ],
    },
  ];

  const menu = Menu.buildFromTemplate(template);
  Menu.setApplicationMenu(menu);
}

// IPC Handlers
ipcMain.handle('show-notification', (event, { title, body }) => {
  try {
    if (Notification.isSupported()) {
      const notif = new Notification({
        title: title || 'Rakshak Security Alert',
        body: body || 'A security event was detected on your host.',
        silent: false,
      });
      notif.on('click', () => {
        if (mainWindow) {
          mainWindow.show();
          mainWindow.focus();
        }
      });
      notif.show();
      return true;
    }
  } catch (err) {
    console.error('[Notification Error]', err.message);
  }
  return false;
});

ipcMain.handle('open-external', (event, url) => {
  if (url && (url.startsWith('http://') || url.startsWith('https://'))) {
    shell.openExternal(url);
    return true;
  }
  return false;
});

ipcMain.handle('get-app-version', () => app.getVersion());

// Lifecycle
app.whenReady().then(() => {
  setupApplicationMenu();
  createMainWindow();
  createTray();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createMainWindow();
    } else if (mainWindow) {
      mainWindow.show();
      mainWindow.focus();
    }
  });
});

app.on('before-quit', () => {
  isQuitting = true;
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
