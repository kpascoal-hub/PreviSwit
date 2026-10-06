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
import React, { useState, useEffect } from 'react';

export default function SettingsPage() {
  const [apiStatus, setApiStatus] = useState('Verificando...');
  const [apiClass, setApiClass] = useState('bg-yellow-500/15 text-yellow-400 border-yellow-500/25');

  useEffect(() => {
    async function checkApiStatus() {
      try {
        await fetch('/api/v1/assets/');
        setApiStatus('Online');
        setApiClass('bg-green-500/15 text-green-400 border-green-500/25');
      } catch {
        setApiStatus('Offline');
        setApiClass('bg-red-500/15 text-red-400 border-red-500/25');
      }
    }
    checkApiStatus();
  }, []);

  return (
    <div className="flex flex-col h-full">
      <div className="mb-6">
        <h2 className="text-xl font-semibold text-white">Configurações</h2>
        <p className="text-sm text-gray-500 mt-1">Configurações da plataforma, usuários e controle de acesso.</p>
      </div>
      <div className="grid grid-cols-2 gap-6">
        <div className="bg-[#0d1421] border border-white/5 rounded-xl p-6">
          <h3 className="text-sm font-semibold text-gray-300 mb-4">Organização</h3>
          <div className="space-y-4">
            <div>
              <label className="block text-xs text-gray-500 mb-1">Nome da Organização</label>
              <input type="text" defaultValue="PreviSwit Organization" className="w-full bg-[#060b13] border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500/50" />
            </div>
            <div>
              <label className="block text-xs text-gray-500 mb-1">Timezone</label>
              <input type="text" defaultValue="America/Sao_Paulo" className="w-full bg-[#060b13] border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500/50" />
            </div>
          </div>
        </div>
        <div className="bg-[#0d1421] border border-white/5 rounded-xl p-6">
          <h3 className="text-sm font-semibold text-gray-300 mb-4">Usuários & RBAC</h3>
          <div className="space-y-3">
            <div className="flex items-center justify-between py-2 border-b border-white/5">
              <div>
                <p className="text-sm text-white">admin</p>
                <p className="text-xs text-gray-500">Administrador do Sistema</p>
              </div>
              <span className="text-xs bg-indigo-500/15 text-indigo-400 border border-indigo-500/25 px-2 py-1 rounded-full">admin</span>
            </div>
          </div>
        </div>
        <div className="bg-[#0d1421] border border-white/5 rounded-xl p-6 col-span-2">
          <h3 className="text-sm font-semibold text-gray-300 mb-4">API & Integrações</h3>
          <div className="flex items-center justify-between py-2">
            <div>
              <p className="text-sm text-white">API REST (PreviSwit Server)</p>
              <p className="text-xs text-gray-500 font-mono">http://localhost:10200</p>
            </div>
            <span className={`text-xs border px-2 py-1 rounded-full ${apiClass}`}>{apiStatus}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
