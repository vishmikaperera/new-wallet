import { useEffect, useMemo, useState } from 'react';
import { api } from '../lib/api';
import { deriveKeyFromPassword, encryptString, decryptString } from '../lib/crypto';

type VaultItem = {
  id: string;
  title: string | null;
  username: string | null;
  url: string | null;
  note: string | null;
  iv: string;
  encryptedData: string;
};

export default function Vault() {
  const [masterPassword, setMasterPassword] = useState('');
  const [vaultSalt, setVaultSalt] = useState<string | null>(null);
  const [items, setItems] = useState<VaultItem[]>([]);
  const [decrypted, setDecrypted] = useState<Record<string, string>>({});
  const [form, setForm] = useState({ title: '', username: '', url: '', note: '', password: '' });

  const keyPromise = useMemo(async () => {
    if (!vaultSalt || !masterPassword) return null as CryptoKey | null;
    try {
      return await deriveKeyFromPassword(masterPassword, vaultSalt);
    } catch {
      return null;
    }
  }, [masterPassword, vaultSalt]);

  useEffect(() => {
    (async () => {
      try {
        const me = await api.get('/api/me');
        setVaultSalt(me.data.vaultSalt);
        const res = await api.get('/api/vault/items');
        setItems(res.data);
      } catch (e) {
        // not signed in
      }
    })();
  }, []);

  async function refresh() {
    const res = await api.get('/api/vault/items');
    setItems(res.data);
  }

  async function addItem(e: React.FormEvent) {
    e.preventDefault();
    if (!vaultSalt || !masterPassword) {
      alert('Enter master password to derive key');
      return;
    }
    const key = await keyPromise;
    if (!key) return;
    const plain = JSON.stringify({ password: form.password });
    const { ivB64, dataB64 } = await encryptString(plain, key);
    const res = await api.post('/api/vault/items', {
      title: form.title,
      username: form.username,
      url: form.url,
      note: form.note,
      iv: ivB64,
      encryptedData: dataB64,
    });
    setItems([res.data, ...items]);
    setForm({ title: '', username: '', url: '', note: '', password: '' });
  }

  async function decryptItem(item: VaultItem) {
    if (!masterPassword || !vaultSalt) return;
    const key = await keyPromise;
    if (!key) return;
    try {
      const text = await decryptString(item.encryptedData, item.iv, key);
      const obj = JSON.parse(text);
      setDecrypted((d) => ({ ...d, [item.id]: obj.password }));
    } catch {
      alert('Failed to decrypt. Check master password.');
    }
  }

  async function removeItem(id: string) {
    await api.delete(`/api/vault/items/${id}`);
    setItems(items.filter((i) => i.id !== id));
  }

  return (
    <div>
      <h3>Vault</h3>
      <div style={{ marginBottom: 16 }}>
        <input placeholder="master password (same as login by default)" type="password" value={masterPassword} onChange={(e) => setMasterPassword(e.target.value)} />
      </div>

      <form onSubmit={addItem} style={{ display: 'grid', gap: 8, maxWidth: 600, marginBottom: 24 }}>
        <input placeholder="title" value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} />
        <input placeholder="username" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
        <input placeholder="url" value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} />
        <input placeholder="note" value={form.note} onChange={(e) => setForm({ ...form, note: e.target.value })} />
        <input placeholder="password to store" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
        <button type="submit">Add</button>
      </form>

      <ul style={{ display: 'grid', gap: 12, listStyle: 'none', padding: 0 }}>
        {items.map((item) => (
          <li key={item.id} style={{ border: '1px solid #ddd', padding: 12, borderRadius: 8 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <strong>{item.title || '(no title)'}</strong>
              <button onClick={() => removeItem(item.id)}>Delete</button>
            </div>
            <div>Username: {item.username || '-'}</div>
            <div>URL: {item.url || '-'}</div>
            <div>Note: {item.note || '-'}</div>
            <div>
              Stored password: {decrypted[item.id] ? (
                <code>{decrypted[item.id]}</code>
              ) : (
                <button onClick={() => decryptItem(item)}>Reveal</button>
              )}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}