const { ipcMain } = require('electron');
const { authenticator } = require('otplib');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const logger = require('electron-log');
const Store = require('electron-store');

const store = new Store();
let db;
let initialized = false;

class IpcHandler {
    static async initialize() {
        if (initialized) {
            logger.info('IPC handlers already initialized, skipping...');
            return;
        }

        logger.info('Initializing IPC handlers...');

        try {
            // Remove any existing handlers to prevent duplicates
            const handlers = ['authenticate', 'addPassword', 'getPasswords', 'updatePassword', 'deletePassword', 'generateOTP'];
            handlers.forEach(handler => {
                try {
                    ipcMain.removeHandler(handler);
                } catch (error) {
                    // Ignore if handler doesn't exist
                }
            });
            
            // Authentication handlers
            ipcMain.handle('authenticate', async (event, { password }) => {
                try {
                    const hashedPassword = store.get('masterPassword');
                    if (!hashedPassword) {
                        const salt = await bcrypt.genSalt(10);
                        const hash = await bcrypt.hash(password, salt);
                        store.set('masterPassword', hash);
                        return true;
                    }
                    return bcrypt.compare(password, hashedPassword);
                } catch (error) {
                    logger.error('Authentication error:', error);
                    throw error;
                }
            });

            initialized = true;
            logger.info('IPC handlers initialized successfully');
        } catch (error) {
            logger.error('Error initializing IPC handlers:', error);
            throw error;
        }
    }
            const hashedPassword = store.get('masterPassword');
            if (!hashedPassword) {
                const salt = await bcrypt.genSalt(10);
                const hash = await bcrypt.hash(password, salt);
                store.set('masterPassword', hash);
                return true;
            }
            return bcrypt.compare(password, hashedPassword);
        });

        // Password management handlers
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
                        passwordData.password,
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

        // Get all passwords
        ipcMain.handle('getPasswords', () => {
            return new Promise((resolve, reject) => {
                db.all('SELECT * FROM passwords ORDER BY updated_at DESC', (err, rows) => {
                    if (err) reject(err);
                    else resolve(rows);
                });
            });
        });

        // Delete password
        ipcMain.handle('deletePassword', async (event, id) => {
            return new Promise((resolve, reject) => {
                db.run('DELETE FROM passwords WHERE id = ?', [id], (err) => {
                    if (err) reject(err);
                    else resolve();
                });
            });
        });

        // OTP generation
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
    }

    static setDatabase(database) {
        db = database;
    }

    static cleanup() {
        if (initialized) {
            ipcMain.removeHandler('authenticate');
            ipcMain.removeHandler('addPassword');
            ipcMain.removeHandler('getPasswords');
            ipcMain.removeHandler('deletePassword');
            ipcMain.removeHandler('generateOTP');
            ipcMain.removeHandler('exportPasswords');
            ipcMain.removeHandler('importPasswords');
            initialized = false;
        }
    }
}

module.exports = IpcHandler;
