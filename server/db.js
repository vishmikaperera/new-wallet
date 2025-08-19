const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.join(__dirname, 'data.sqlite');
const db = new Database(dbPath);

db.pragma('journal_mode = WAL');

// users table: stores auth credentials and salts for client-side key derivation
// webauthn_credentials table: multiple credentials per user
// vault_items table: encrypted payloads stored per user

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  passwordHash TEXT NOT NULL,
  totpSecret TEXT,
  webauthnUserId TEXT NOT NULL,
  vaultSalt TEXT NOT NULL,
  createdAt INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
  id TEXT PRIMARY KEY,
  userId TEXT NOT NULL,
  credentialId TEXT NOT NULL,
  publicKey TEXT NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  transports TEXT,
  createdAt INTEGER NOT NULL,
  FOREIGN KEY(userId) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE(credentialId)
);

CREATE TABLE IF NOT EXISTS vault_items (
  id TEXT PRIMARY KEY,
  userId TEXT NOT NULL,
  title TEXT,
  username TEXT,
  url TEXT,
  note TEXT,
  iv TEXT NOT NULL,
  encryptedData TEXT NOT NULL,
  createdAt INTEGER NOT NULL,
  updatedAt INTEGER NOT NULL,
  FOREIGN KEY(userId) REFERENCES users(id) ON DELETE CASCADE
);
`);

module.exports = { db };