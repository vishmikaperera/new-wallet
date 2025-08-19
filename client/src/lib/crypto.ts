export async function deriveKeyFromPassword(password: string, saltB64: string): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const pwdKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  const salt = Uint8Array.from(atob(saltB64), (c) => c.charCodeAt(0));
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 150000, hash: 'SHA-256' },
    pwdKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptString(plainText: string, key: CryptoKey): Promise<{ ivB64: string; dataB64: string }> {
  const enc = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plainText));
  const dataB64 = btoa(String.fromCharCode(...new Uint8Array(cipher)));
  const ivB64 = btoa(String.fromCharCode(...iv));
  return { ivB64, dataB64 };
}

export async function decryptString(dataB64: string, ivB64: string, key: CryptoKey): Promise<string> {
  const dec = new TextDecoder();
  const data = Uint8Array.from(atob(dataB64), (c) => c.charCodeAt(0));
  const iv = Uint8Array.from(atob(ivB64), (c) => c.charCodeAt(0));
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
  return dec.decode(plain);
}