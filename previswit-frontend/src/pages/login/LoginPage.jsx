/*
 * PreviSwit AI-ASPM
 * Copyright (C) 2026 PreviSwit Team
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldAlert, ArrowLeft } from 'lucide-react';
import SplashScreen from './SplashScreen';

export default function LoginPage({ setIsAuthenticated }) {
  const [view, setView] = useState('login'); // 'login' | 'forgot'

  // Login State
  const [loginUser, setLoginUser] = useState('');
  const [loginPass, setLoginPass] = useState('');
  const [loginError, setLoginError] = useState(false);
  const [showSplash, setShowSplash] = useState(false);

  // Forgot Password State
  const [forgotEmail, setForgotEmail] = useState('');
  const [forgotStatus, setForgotStatus] = useState(null); // 'loading' | 'success' | 'error'
  const [forgotMessage, setForgotMessage] = useState('');

  const navigate = useNavigate();

  const handleLogin = (e) => {
    e.preventDefault();
    if (loginUser === 'admin' && loginPass === 'admin') {
      setLoginError(false);
      setShowSplash(true);
      setTimeout(() => {
        setIsAuthenticated(true);
        navigate('/');
      }, 1300);
    } else {
      setLoginError(true);
    }
  };

  const handleForgotPassword = async (e) => {
    e.preventDefault();
    setForgotStatus('loading');
    setForgotMessage('');
    
    try {
      const res = await fetch('/api/v1/auth/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: forgotEmail })
      });
      
      const data = await res.json();
      
      if (res.ok) {
        setForgotStatus('success');
        setForgotMessage(data.message || 'Verifique o seu e-mail para as instruções de recuperação.');
      } else {
        setForgotStatus('error');
        setForgotMessage(data.detail || 'Ocorreu um erro ao solicitar a recuperação.');
      }
    } catch (err) {
      setForgotStatus('error');
      setForgotMessage('Erro de conexão com o servidor.');
    }
  };

  const resetToLogin = () => {
    setView('login');
    setForgotStatus(null);
    setForgotMessage('');
    setForgotEmail('');
  };

  return (
    <>
    {showSplash && <SplashScreen />}
    <div className="min-h-screen flex items-center justify-center relative overflow-hidden bg-[#060b13]">
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-blue-900/20 via-[#060b13] to-[#060b13]"></div>
      <div className="glass-panel w-full max-w-md p-10 relative z-10">
        <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-blue-600 to-emerald-500 rounded-t-xl"></div>
        <div className="mb-10 flex flex-col items-center text-center">
          <ShieldAlert className="w-12 h-12 text-blue-500 mb-4" />
          <h1 className="text-3xl font-bold text-white mb-2">PreviSwit</h1>
          <p className="text-xs text-gray-400 uppercase tracking-widest font-semibold">
            {view === 'login' ? 'Autenticação do Sistema' : 'Recuperação de Acesso'}
          </p>
        </div>

        {view === 'login' ? (
          <>
            {loginError && (
              <div className="mb-6 p-4 rounded bg-red-500/10 border border-red-500/30 text-red-400 text-sm text-center font-medium">
                Credenciais inválidas.
              </div>
            )}

            <form onSubmit={handleLogin} className="space-y-6">
              <div>
                <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Identificador</label>
                <input type="text" required value={loginUser} onChange={(e) => setLoginUser(e.target.value)}
                  className="w-full bg-[#03050a]/60 border border-gray-700/50 rounded px-4 py-3 text-white focus:outline-none focus:border-blue-500/80" />
              </div>
              <div>
                <div className="flex justify-between items-center mb-2">
                  <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider">Chave de Segurança</label>
                  <button type="button" onClick={() => setView('forgot')} className="text-xs text-blue-500 hover:text-blue-400 transition-colors">
                    Esqueceu a senha?
                  </button>
                </div>
                <input type="password" required value={loginPass} onChange={(e) => setLoginPass(e.target.value)}
                  className="w-full bg-[#03050a]/60 border border-gray-700/50 rounded px-4 py-3 text-white focus:outline-none focus:border-blue-500/80" />
              </div>
              <button type="submit" className="w-full bg-blue-600 text-white font-bold py-3 rounded hover:bg-blue-500 transition-colors mt-4 shadow-lg shadow-blue-900/20">
                Acessar Plataforma
              </button>
            </form>
          </>
        ) : (
          <>
            {forgotStatus === 'success' && (
              <div className="mb-6 p-4 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-sm text-center font-medium">
                {forgotMessage}
              </div>
            )}
            
            {forgotStatus === 'error' && (
              <div className="mb-6 p-4 rounded bg-red-500/10 border border-red-500/30 text-red-400 text-sm text-center font-medium">
                {forgotMessage}
              </div>
            )}

            <form onSubmit={handleForgotPassword} className="space-y-6">
              <div>
                <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">E-mail Cadastrado</label>
                <input type="email" required value={forgotEmail} onChange={(e) => setForgotEmail(e.target.value)}
                  disabled={forgotStatus === 'loading'}
                  placeholder="seu@email.com"
                  className="w-full bg-[#03050a]/60 border border-gray-700/50 rounded px-4 py-3 text-white focus:outline-none focus:border-blue-500/80 disabled:opacity-50" />
              </div>
              
              <button type="submit" disabled={forgotStatus === 'loading'} className="w-full bg-blue-600 text-white font-bold py-3 rounded hover:bg-blue-500 transition-colors mt-4 shadow-lg shadow-blue-900/20 disabled:opacity-50 flex justify-center items-center">
                {forgotStatus === 'loading' ? (
                  <span className="w-5 h-5 border-2 border-white/20 border-t-white rounded-full animate-spin"></span>
                ) : (
                  'Solicitar Recuperação'
                )}
              </button>
              
              <div className="text-center mt-6">
                <button type="button" onClick={resetToLogin} className="text-sm text-gray-400 hover:text-white transition-colors flex items-center justify-center gap-2 mx-auto">
                  <ArrowLeft className="w-4 h-4" />
                  Voltar ao Login
                </button>
              </div>
            </form>
          </>
        )}
      </div>
    </div>
    </>
  );
}
