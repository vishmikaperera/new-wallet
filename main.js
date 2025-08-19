const { app, BrowserWindow, ipcMain, systemPreferences } = require('electron');
const path = require('path');
const Store = require('electron-store');
const bcrypt = require('bcrypt');
const { initializeDatabase } = require('./src/config/database');
const IpcHandler = require('./src/controllers/IpcHandler');
const logger = require('electron-log');

// Initialize store for settings
const store = new Store();

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      enableRemoteModule: true
    }
  });

  mainWindow.loadFile('index.html');

  // Enable DevTools in development
  if (process.env.NODE_ENV === 'development') {
    mainWindow.webContents.openDevTools();
  }
}

// Initialize app
app.whenReady().then(async () => {
    try {
        // Initialize database
        const db = await initializeDatabase();
        logger.info('Database initialized successfully');

        // Set database and initialize IPC handlers
        IpcHandler.setDatabase(db);
        await IpcHandler.initialize();
        logger.info('IPC handlers initialized successfully');

        // Create main window
        await createWindow();
        logger.info('Main window created successfully');

    } catch (error) {
        logger.error('Error during application startup:', error);
        app.quit();
    }
});

// Handle any uncaught exceptions
process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception:', error);
});

// Handle any unhandled promise rejections
process.on('unhandledRejection', (error) => {
    logger.error('Unhandled Rejection:', error);
});

// Cleanup when app quits
app.on('before-quit', () => {
    IpcHandler.cleanup();
});

// Quit when all windows are closed
app.on('window-all-closed', () => {
  IpcHandler.cleanup();
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

// IPC Handlers
ipcMain.handle('authenticate', async (event, { password }) => {
  const hashedPassword = store.get('masterPassword');
  if (!hashedPassword) {
    // First time setup
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);
    store.set('masterPassword', hash);
    return true;
  }
  
  return bcrypt.compare(password, hashedPassword);
});

ipcMain.handle('checkBiometricAvailability', () => {
  // Check if the system supports biometric authentication
  return process.platform === 'darwin' || process.platform === 'win32';
});

ipcMain.handle('authenticateWithBiometric', async () => {
  try {
    // Implement system-specific biometric authentication
    if (process.platform === 'darwin') {
      // Implement Touch ID for macOS
      const { systemPreferences } = require('electron');
      return await systemPreferences.promptTouchID('Unlock Password Wallet');
    } else if (process.platform === 'win32') {
      // Implement Windows Hello
      // This would require a native module for Windows Hello integration
      return false;
    }
    return false;
  } catch (error) {
    console.error('Biometric authentication failed:', error);
    return false;
  }
});

// Password Management
ipcMain.handle('addPassword', async (event, passwordData) => {
  return new Promise((resolve, reject) => {
    const id = uuidv4();
    const now = Date.now();
    
    db.run(
      `INSERT INTO passwords (id, title, username, password, url, category, otp_secret, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        id,
        passwordData.title,
        passwordData.username,
        passwordData.password, // Note: Password should be encrypted before storage
        passwordData.url,
        passwordData.category,
        passwordData.otpSecret,
        now,
        now
      ],
      (err) => {
        if (err) reject(err);
        else resolve(id);
      }
    );
  });
});

ipcMain.handle('getPasswords', () => {
  return new Promise((resolve, reject) => {
    db.all('SELECT * FROM passwords ORDER BY updated_at DESC', (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
});

ipcMain.handle('deletePassword', async (event, id) => {
  return new Promise((resolve, reject) => {
    db.run('DELETE FROM passwords WHERE id = ?', [id], (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
});

ipcMain.handle('generateOTP', async (event, secret) => {
  return authenticator.generate(secret);
});

// Export functionality
ipcMain.handle('exportPasswords', async () => {
  return new Promise((resolve, reject) => {
    db.all('SELECT * FROM passwords', (err, rows) => {
      if (err) reject(err);
      else {
        const exportData = {
          version: '1.0',
          timestamp: Date.now(),
          passwords: rows
        };
        resolve(exportData);
      }
    });
  });
});

// Import functionality
ipcMain.handle('importPasswords', async (event, data) => {
  return new Promise((resolve, reject) => {
    if (!data.version || !data.passwords || !Array.isArray(data.passwords)) {
      reject(new Error('Invalid import data format'));
      return;
    }

    const stmt = db.prepare(
      `INSERT INTO passwords (id, title, username, password, url, category, otp_secret, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );

    db.serialize(() => {
      db.run('BEGIN TRANSACTION');
      
      data.passwords.forEach((pwd) => {
        stmt.run([
          uuidv4(),
          pwd.title,
          pwd.username,
          pwd.password,
          pwd.url,
          pwd.category,
          pwd.otpSecret,
          pwd.created_at || Date.now(),
          pwd.updated_at || Date.now()
        ]);
      });

      db.run('COMMIT', (err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    stmt.finalize();
  });
});
