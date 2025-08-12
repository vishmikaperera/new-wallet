import { useState } from 'react';
import { api } from '../lib/api';
import { startRegistration } from '@simplewebauthn/browser';

export default function Register() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [qr, setQr] = useState<string | null>(null);
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [vaultSalt, setVaultSalt] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  async function onRegister(e: React.FormEvent) {
    e.preventDefault();
    setMessage(null);
    const res = await api.post('/api/auth/register', { email, password });
    setQr(res.data.totp.qrDataUrl);
    setMfaToken(res.data.mfaToken);
    setVaultSalt(res.data.vaultSalt);
    setMessage('Scan the QR in your authenticator app, then optionally add a biometric credential.');
  }

  async function addBiometric() {
    if (!mfaToken) return;
    const { data: options } = await api.get('/api/webauthn/generate-registration-options', { params: { mfaToken } });
    const attResp = await startRegistration(options);
    await api.post('/api/webauthn/verify-registration', { mfaToken, attResp });
    setMessage('Biometric credential added and session created. You can proceed to the Vault.');
  }

  return (
    <div>
      <h3>Create account</h3>
      <form onSubmit={onRegister} style={{ display: 'grid', gap: 8, maxWidth: 400 }}>
        <input placeholder="email" value={email} onChange={(e) => setEmail(e.target.value)} />
        <input placeholder="password (min 8 chars)" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        <button type="submit">Register</button>
      </form>
      {qr && (
        <div style={{ marginTop: 16 }}>
          <p>Scan this QR with Google Authenticator, Authy, etc.</p>
          <img src={qr} alt="TOTP QR" style={{ width: 200, height: 200 }} />
        </div>
      )}
      {mfaToken && (
        <div style={{ marginTop: 16 }}>
          <button onClick={addBiometric}>Add biometric (WebAuthn)</button>
        </div>
      )}
      {message && <p style={{ marginTop: 12 }}>{message}</p>}
    </div>
  );
}