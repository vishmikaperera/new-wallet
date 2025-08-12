import { useState } from 'react';
import { api } from '../lib/api';
import { startAuthentication } from '@simplewebauthn/browser';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [otp, setOtp] = useState('');
  const [info, setInfo] = useState<string | null>(null);

  async function onLogin(e: React.FormEvent) {
    e.preventDefault();
    setInfo(null);
    const res = await api.post('/api/auth/login', { email, password });
    setMfaToken(res.data.mfaToken);
    setInfo('Choose OTP or Biometric to finalize sign-in.');
  }

  async function verifyOtp() {
    if (!mfaToken) return;
    await api.post('/api/auth/otp/verify', { mfaToken, otp });
    setInfo('Signed in. Proceed to the Vault.');
  }

  async function signInWithBiometric() {
    if (!mfaToken) return;
    const { data: options } = await api.get('/api/webauthn/generate-authentication-options', { params: { mfaToken } });
    const assertionResp = await startAuthentication(options);
    await api.post('/api/webauthn/verify-authentication', { mfaToken, assertionResp });
    setInfo('Signed in. Proceed to the Vault.');
  }

  return (
    <div>
      <h3>Login</h3>
      <form onSubmit={onLogin} style={{ display: 'grid', gap: 8, maxWidth: 400 }}>
        <input placeholder="email" value={email} onChange={(e) => setEmail(e.target.value)} />
        <input placeholder="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        <button type="submit">Continue</button>
      </form>

      {mfaToken && (
        <div style={{ marginTop: 16, display: 'grid', gap: 8, maxWidth: 400 }}>
          <div>
            <input placeholder="6-digit OTP" value={otp} onChange={(e) => setOtp(e.target.value)} maxLength={6} />
            <button onClick={verifyOtp}>Verify OTP</button>
          </div>
          <div>
            <button onClick={signInWithBiometric}>Use biometric (WebAuthn)</button>
          </div>
        </div>
      )}

      {info && <p style={{ marginTop: 12 }}>{info}</p>}
    </div>
  );
}