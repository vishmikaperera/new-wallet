require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { z } = require('zod');
const jwt = require('jsonwebtoken');
const argon2 = require('argon2');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const { v4: uuidv4 } = require('uuid');
const { db } = require('./db');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const app = express();
const PORT = process.env.PORT || 4000;
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || 'http://localhost:5173';
const JWT_SECRET = process.env.JWT_SECRET || 'dev_jwt_secret_change_me';
const RP_ID = process.env.RP_ID || 'localhost';
const RP_NAME = process.env.RP_NAME || 'My Password Wallet';

app.use(cors({ origin: CLIENT_ORIGIN, credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

// In-memory store for challenges during WebAuthn flows
const challengeStoreByUserId = new Map();

function nowMs() {
  return Date.now();
}

function signSessionJwt(userId) {
  return jwt.sign({ sub: userId, type: 'session' }, JWT_SECRET, { expiresIn: '7d' });
}

function signMfaJwt(userId) {
  return jwt.sign({ sub: userId, type: 'mfa' }, JWT_SECRET, { expiresIn: '10m' });
}

function authRequired(req, res, next) {
  const token = req.cookies['session'];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.type !== 'session') throw new Error('Invalid token');
    req.userId = payload.sub;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

// DB helpers
const insertUserStmt = db.prepare(
  'INSERT INTO users (id, email, passwordHash, totpSecret, webauthnUserId, vaultSalt, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?)'
);
const getUserByEmailStmt = db.prepare('SELECT * FROM users WHERE email = ?');
const getUserByIdStmt = db.prepare('SELECT * FROM users WHERE id = ?');

const insertCredStmt = db.prepare(
  'INSERT INTO webauthn_credentials (id, userId, credentialId, publicKey, counter, transports, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?)'
);
const getCredsByUserStmt = db.prepare('SELECT * FROM webauthn_credentials WHERE userId = ?');
const getCredByCredIdStmt = db.prepare('SELECT * FROM webauthn_credentials WHERE credentialId = ?');
const updateCredCounterStmt = db.prepare('UPDATE webauthn_credentials SET counter = ? WHERE id = ?');

const insertItemStmt = db.prepare(
  'INSERT INTO vault_items (id, userId, title, username, url, note, iv, encryptedData, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
);
const getItemsByUserStmt = db.prepare('SELECT * FROM vault_items WHERE userId = ? ORDER BY updatedAt DESC');
const getItemByIdStmt = db.prepare('SELECT * FROM vault_items WHERE id = ? AND userId = ?');
const updateItemStmt = db.prepare(
  'UPDATE vault_items SET title = ?, username = ?, url = ?, note = ?, iv = ?, encryptedData = ?, updatedAt = ? WHERE id = ? AND userId = ?'
);
const deleteItemStmt = db.prepare('DELETE FROM vault_items WHERE id = ? AND userId = ?');

// Schemas
const RegisterBody = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

const LoginBody = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

const OtpVerifyBody = z.object({
  mfaToken: z.string(),
  otp: z.string().min(6).max(6),
});

const CreateItemBody = z.object({
  title: z.string().optional(),
  username: z.string().optional(),
  url: z.string().optional(),
  note: z.string().optional(),
  iv: z.string(),
  encryptedData: z.string(),
});

const UpdateItemBody = CreateItemBody;

// Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password } = RegisterBody.parse(req.body);

    const existing = getUserByEmailStmt.get(email);
    if (existing) return res.status(400).json({ error: 'Email already registered' });

    const userId = uuidv4();
    const passwordHash = await argon2.hash(password);

    const crypto = require('crypto');
    const vaultSalt = crypto.randomBytes(16).toString('base64');

    // TOTP secret
    const totpSecret = speakeasy.generateSecret({ name: `${RP_NAME} (${email})` });
    const otpAuthUrl = totpSecret.otpauth_url;
    const qrDataUrl = await qrcode.toDataURL(otpAuthUrl);

    const webauthnUserId = uuidv4();

    insertUserStmt.run(
      userId,
      email,
      passwordHash,
      totpSecret.base32,
      webauthnUserId,
      vaultSalt,
      nowMs()
    );

    const mfaToken = signMfaJwt(userId);

    res.json({
      mfaToken,
      totp: { qrDataUrl, secretBase32: totpSecret.base32 },
      vaultSalt,
    });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: 'Invalid request' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = LoginBody.parse(req.body);
    const user = getUserByEmailStmt.get(email);
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });
    const ok = await argon2.verify(user.passwordHash, password);
    if (!ok) return res.status(400).json({ error: 'Invalid credentials' });

    const mfaToken = signMfaJwt(user.id);
    res.json({ mfaToken, methods: { otp: !!user.totpSecret, webauthn: true }, vaultSalt: user.vaultSalt });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: 'Invalid request' });
  }
});

app.post('/api/auth/otp/verify', (req, res) => {
  try {
    const { mfaToken, otp } = OtpVerifyBody.parse(req.body);
    const payload = jwt.verify(mfaToken, JWT_SECRET);
    if (payload.type !== 'mfa') throw new Error('Invalid token');

    const user = getUserByIdStmt.get(payload.sub);
    if (!user) return res.status(400).json({ error: 'User not found' });

    const verified = speakeasy.totp.verify({ secret: user.totpSecret, encoding: 'base32', token: otp, window: 1 });
    if (!verified) return res.status(400).json({ error: 'Invalid code' });

    const session = signSessionJwt(user.id);
    res.cookie('session', session, { httpOnly: true, sameSite: 'lax', secure: false, maxAge: 7 * 24 * 3600 * 1000 });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: 'Invalid request' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('session');
  res.json({ ok: true });
});

// WebAuthn registration
app.get('/api/webauthn/generate-registration-options', (req, res) => {
  try {
    const mfaToken = req.query.mfaToken;
    if (!mfaToken) return res.status(400).json({ error: 'Missing mfaToken' });
    const payload = jwt.verify(mfaToken, JWT_SECRET);
    if (payload.type !== 'mfa') throw new Error('Invalid token');
    const user = getUserByIdStmt.get(payload.sub);
    if (!user) return res.status(400).json({ error: 'User not found' });

    const userCreds = getCredsByUserStmt.all(user.id);

    const options = generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userID: user.webauthnUserId,
      userName: user.email,
      attestationType: 'none',
      excludeCredentials: userCreds.map((c) => ({ id: Buffer.from(c.credentialId, 'base64url'), type: 'public-key' })),
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
    });

    challengeStoreByUserId.set(user.id, options.challenge);
    res.json(options);
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: 'Failed to generate options' });
  }
});

app.post('/api/webauthn/verify-registration', async (req, res) => {
  try {
    const { mfaToken, attResp } = req.body;
    if (typeof mfaToken !== 'string' || !attResp) return res.status(400).json({ error: 'Invalid body' });
    const payload = jwt.verify(mfaToken, JWT_SECRET);
    if (payload.type !== 'mfa') throw new Error('Invalid token');

    const user = getUserByIdStmt.get(payload.sub);
    if (!user) return res.status(400).json({ error: 'User not found' });

    const expectedChallenge = challengeStoreByUserId.get(user.id);

    const verification = await verifyRegistrationResponse({
      response: attResp,
      expectedChallenge,
      expectedOrigin: process.env.CLIENT_ORIGIN || `http://${RP_ID}:5173`,
      expectedRPID: RP_ID,
    });

    if (!verification.verified || !verification.registrationInfo) {
      return res.status(400).json({ error: 'Verification failed' });
    }

    const {
      credentialID,
      credentialPublicKey,
      counter,
      credentialDeviceType,
      credentialBackedUp,
      transports,
    } = verification.registrationInfo;

    insertCredStmt.run(
      uuidv4(),
      user.id,
      Buffer.from(credentialID).toString('base64url'),
      Buffer.from(credentialPublicKey).toString('base64url'),
      counter || 0,
      transports ? JSON.stringify(transports) : null,
      nowMs()
    );

    const session = signSessionJwt(user.id);
    res.cookie('session', session, { httpOnly: true, sameSite: 'lax', secure: false, maxAge: 7 * 24 * 3600 * 1000 });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: 'Verification error' });
  }
});

// WebAuthn authentication
app.get('/api/webauthn/generate-authentication-options', (req, res) => {
  try {
    const mfaToken = req.query.mfaToken;
    if (!mfaToken) return res.status(400).json({ error: 'Missing mfaToken' });
    const payload = jwt.verify(mfaToken, JWT_SECRET);
    if (payload.type !== 'mfa') throw new Error('Invalid token');
    const user = getUserByIdStmt.get(payload.sub);
    if (!user) return res.status(400).json({ error: 'User not found' });

    const creds = getCredsByUserStmt.all(user.id);

    const options = generateAuthenticationOptions({
      rpID: RP_ID,
      userVerification: 'preferred',
      allowCredentials: creds.map((c) => ({ id: Buffer.from(c.credentialId, 'base64url'), type: 'public-key' })),
    });

    challengeStoreByUserId.set(user.id, options.challenge);
    res.json(options);
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: 'Failed to generate options' });
  }
});

app.post('/api/webauthn/verify-authentication', async (req, res) => {
  try {
    const { mfaToken, assertionResp } = req.body;
    if (typeof mfaToken !== 'string' || !assertionResp) return res.status(400).json({ error: 'Invalid body' });
    const payload = jwt.verify(mfaToken, JWT_SECRET);
    if (payload.type !== 'mfa') throw new Error('Invalid token');

    const user = getUserByIdStmt.get(payload.sub);
    if (!user) return res.status(400).json({ error: 'User not found' });

    const expectedChallenge = challengeStoreByUserId.get(user.id);

    const cred = getCredByCredIdStmt.get(assertionResp.id);
    if (!cred) return res.status(400).json({ error: 'Unknown credential' });

    const verification = await verifyAuthenticationResponse({
      response: assertionResp,
      expectedChallenge,
      expectedOrigin: process.env.CLIENT_ORIGIN || `http://${RP_ID}:5173`,
      expectedRPID: RP_ID,
      authenticator: {
        credentialID: Buffer.from(cred.credentialId, 'base64url'),
        credentialPublicKey: Buffer.from(cred.publicKey, 'base64url'),
        counter: cred.counter,
        transports: cred.transports ? JSON.parse(cred.transports) : undefined,
      },
    });

    if (!verification.verified || !verification.authenticationInfo) {
      return res.status(400).json({ error: 'Verification failed' });
    }

    const { newCounter } = verification.authenticationInfo;
    updateCredCounterStmt.run(newCounter, cred.id);

    const session = signSessionJwt(user.id);
    res.cookie('session', session, { httpOnly: true, sameSite: 'lax', secure: false, maxAge: 7 * 24 * 3600 * 1000 });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: 'Verification error' });
  }
});

// Me
app.get('/api/me', authRequired, (req, res) => {
  const user = getUserByIdStmt.get(req.userId);
  if (!user) return res.status(404).json({ error: 'Not found' });
  res.json({ email: user.email, vaultSalt: user.vaultSalt });
});

// Vault CRUD
app.get('/api/vault/items', authRequired, (req, res) => {
  const items = getItemsByUserStmt.all(req.userId);
  res.json(items);
});

app.post('/api/vault/items', authRequired, (req, res) => {
  try {
    const body = CreateItemBody.parse(req.body);
    const id = uuidv4();
    const ts = nowMs();
    insertItemStmt.run(
      id,
      req.userId,
      body.title || null,
      body.username || null,
      body.url || null,
      body.note || null,
      body.iv,
      body.encryptedData,
      ts,
      ts
    );
    const item = getItemByIdStmt.get(id, req.userId);
    res.json(item);
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: 'Invalid body' });
  }
});

app.put('/api/vault/items/:id', authRequired, (req, res) => {
  try {
    const body = UpdateItemBody.parse(req.body);
    const ts = nowMs();
    const result = updateItemStmt.run(
      body.title || null,
      body.username || null,
      body.url || null,
      body.note || null,
      body.iv,
      body.encryptedData,
      ts,
      req.params.id,
      req.userId
    );
    if (result.changes === 0) return res.status(404).json({ error: 'Not found' });
    const item = getItemByIdStmt.get(req.params.id, req.userId);
    res.json(item);
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: 'Invalid body' });
  }
});

app.delete('/api/vault/items/:id', authRequired, (req, res) => {
  const result = deleteItemStmt.run(req.params.id, req.userId);
  if (result.changes === 0) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

app.get('/', (_req, res) => {
  res.send('Server running');
});

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});