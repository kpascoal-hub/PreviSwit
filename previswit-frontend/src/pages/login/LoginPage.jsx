import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldAlert } from 'lucide-react';

export default function LoginPage({ setIsAuthenticated }) {
  const [loginUser, setLoginUser] = useState('');
  const [loginPass, setLoginPass] = useState('');
  const [loginError, setLoginError] = useState(false);
  const navigate = useNavigate();

  const handleLogin = (e) => {
    e.preventDefault();
    if (loginUser === 'admin' && loginPass === 'admin') {
      setIsAuthenticated(true);
      setLoginError(false);
      navigate('/');
    } else {
      setLoginError(true);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center relative overflow-hidden bg-[#060b13]">
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-blue-900/20 via-[#060b13] to-[#060b13]"></div>
      <div className="glass-panel w-full max-w-md p-10 relative z-10">
        <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-blue-600 to-emerald-500 rounded-t-xl"></div>
        <div className="mb-10 flex flex-col items-center text-center">
          <ShieldAlert className="w-12 h-12 text-blue-500 mb-4" />
          <h1 className="text-3xl font-bold text-white mb-2">PreviSwit ASPM</h1>
          <p className="text-xs text-gray-400 uppercase tracking-widest font-semibold">Autenticação do Sistema</p>
        </div>
        
        {loginError && (
          <div className="mb-6 p-4 rounded bg-red-500/10 border border-red-500/30 text-red-400 text-sm text-center font-medium">
            Credenciais inválidas.
          </div>
        )}

        <form onSubmit={handleLogin} className="space-y-6">
          <div>
            <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Identificador</label>
            <input type="text" required value={loginUser} onChange={(e)=>setLoginUser(e.target.value)}
              className="w-full bg-[#03050a]/60 border border-gray-700/50 rounded px-4 py-3 text-white focus:outline-none focus:border-blue-500/80" />
          </div>
          <div>
            <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Chave de Segurança</label>
            <input type="password" required value={loginPass} onChange={(e)=>setLoginPass(e.target.value)}
              className="w-full bg-[#03050a]/60 border border-gray-700/50 rounded px-4 py-3 text-white focus:outline-none focus:border-blue-500/80" />
          </div>
          <button type="submit" className="w-full bg-blue-600 text-white font-bold py-3 rounded hover:bg-blue-500 transition-colors mt-4 shadow-lg shadow-blue-900/20">
            Acessar Plataforma
          </button>
        </form>
      </div>
    </div>
  );
}
