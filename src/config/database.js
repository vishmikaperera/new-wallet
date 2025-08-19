const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const logger = require('electron-log');

// Database initialization
function initializeDatabase() {
    return new Promise((resolve, reject) => {
        const db = new sqlite3.Database(path.join(__dirname, '../../data/passwords.db'), (err) => {
            if (err) {
                logger.error('Database connection failed:', err);
                reject(err);
                return;
            }
            logger.info('Connected to the passwords database.');
        });

        // Create passwords table if it doesn't exist
        db.run(`CREATE TABLE IF NOT EXISTS passwords (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            username TEXT,
            password TEXT NOT NULL,
            url TEXT,
            category TEXT,
            otp_secret TEXT,
            created_at INTEGER,
            updated_at INTEGER
        )`, (err) => {
            if (err) {
                logger.error('Error creating passwords table:', err);
                reject(err);
                return;
            }
            logger.info('Passwords table initialized successfully');
            resolve(db);
        });
    });
}

module.exports = {
    initializeDatabase
};
