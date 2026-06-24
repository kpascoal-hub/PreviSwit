/**
 * PreviSwit — Hook: useAuth
 * Context de autenticação com JWT, persistência em localStorage.
 */
import { useState, useCallback } from 'react';

const AUTH_URL = import.meta.env.VITE_API_URL
  ? import.meta.env.VITE_API_URL.replace('/api/v1', '')
  : 'http://localhost:10200';

export function useAuth() {
  const [user, setUser] = useState(() => {
    try {
      const stored = localStorage.getItem('previswit_user');
      return stored ? JSON.parse(stored) : null;
    } catch {
      return null;
    }
  });

  const isAuthenticated = Boolean(user && localStorage.getItem('previswit_token'));

  const login = useCallback(async (username, password) => {
    const formData = new URLSearchParams();
    formData.append('username', username);
    formData.append('password', password);

    const response = await fetch(`${AUTH_URL}/auth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formData,
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({ detail: 'Credenciais inválidas' }));
      throw new Error(err.detail || 'Falha no login');
    }

    const data = await response.json();
    localStorage.setItem('previswit_token', data.access_token);

    const userData = {
      username,
      role: data.role || 'viewer',
      name: data.full_name || username,
    };
    localStorage.setItem('previswit_user', JSON.stringify(userData));
    setUser(userData);
    return userData;
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('previswit_token');
    localStorage.removeItem('previswit_user');
    setUser(null);
  }, []);

  return { user, isAuthenticated, login, logout };
}
