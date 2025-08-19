import { Link, Route, Routes, useNavigate } from 'react-router-dom';
import Register from './pages/Register';
import Login from './pages/Login';
import Vault from './pages/Vault';

export default function App() {
  return (
    <div style={{ maxWidth: 900, margin: '0 auto', padding: 16, fontFamily: 'system-ui, sans-serif' }}>
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <h2>Password Wallet</h2>
        <nav style={{ display: 'flex', gap: 12 }}>
          <Link to="/register">Register</Link>
          <Link to="/login">Login</Link>
          <Link to="/vault">Vault</Link>
        </nav>
      </header>
      <Routes>
        <Route path="/register" element={<Register />} />
        <Route path="/login" element={<Login />} />
        <Route path="/vault" element={<Vault />} />
        <Route path="*" element={<Home />} />
      </Routes>
    </div>
  );
}

function Home() {
  const nav = useNavigate();
  return (
    <div>
      <p>Welcome. Get started by registering, then login with OTP or biometrics.</p>
      <div style={{ display: 'flex', gap: 8 }}>
        <button onClick={() => nav('/register')}>Register</button>
        <button onClick={() => nav('/login')}>Login</button>
      </div>
    </div>
  );
}
