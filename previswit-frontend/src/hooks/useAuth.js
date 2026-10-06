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
/**
 * PreviSwit — Hook: useAuth
 * Context de autenticação com JWT, persistência em localStorage.
 */
import { useState, useCallback } from 'react';

const AUTH_URL = import.meta.env.VITE_API_URL
  ? import.meta.env.VITE_API_URL.replace('/api/v1', '')
  : 'http://localhost:10100';

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
