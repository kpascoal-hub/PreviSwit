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
import React, { useState, useEffect, useRef } from 'react';
import { NavLink, Outlet, useNavigate, useLocation } from 'react-router-dom';
import {
  ShieldAlert, LayoutDashboard, Server, Workflow, TerminalSquare,
  BrainCircuit, TrendingUp, FileText, Puzzle, Settings, LogOut,
  GitBranch, Cloud, Box, Monitor, Globe, ChevronDown,
  CheckCircle, AlertTriangle, X, Terminal,
} from 'lucide-react';

// ── Global Scan Monitor ───────────────────────────────────────────────────────
// Tracks scans started from any panel, shows notifications when they complete.

const PENDING_SCANS_KEY = 'previswit_pending_scans';

function ScanMonitor() {
  const [notifications, setNotifications] = useState([]);
  const activeRef = useRef([]);

  // Sync active scans from localStorage whenever it changes
  const syncActive = () => {
    try {
      return JSON.parse(localStorage.getItem(PENDING_SCANS_KEY) || '[]');
    } catch { return []; }
  };

  useEffect(() => {
    const poll = async () => {
      const scans = syncActive();
      activeRef.current = scans;
      if (scans.length === 0) return;

      const newNotifs = [];
      for (const scan of scans) {
        try {
          const res = await fetch(`/api/v1/sast/scan-status/${scan.scanId}`);
          if (!res.ok) continue;
          const data = await res.json();
          const done = data.status === 'CONCLUÍDO' || data.status === 'ERROR';
          if (done) {
            // Remove from pending
            const remaining = syncActive().filter(s => s.scanId !== scan.scanId);
            localStorage.setItem(PENDING_SCANS_KEY, JSON.stringify(remaining));
            // Save result
            if (data.data) {
              localStorage.setItem('previswit_sast_current_view',
                JSON.stringify({ target: scan.repoName, data: data.data }));
            }
            newNotifs.push({
              id: scan.scanId,
              repoName: scan.repoName,
              status: data.status,
              vulnerable: data.data?.vulnerable,
              error: data.error,
            });
          }
        } catch {}
      }
      if (newNotifs.length > 0) {
        setNotifications(prev => [...prev, ...newNotifs]);
      }
    };

    const iv = setInterval(poll, 5000);
    poll(); // immediate first check
    return () => clearInterval(iv);
  }, []);

  const dismiss = (id) => setNotifications(prev => prev.filter(n => n.id !== id));
  const activeCount = syncActive().length;

  return (
    <>
      {/* Floating "scan running" chip */}
      {activeCount > 0 && (
        <div className="fixed top-4 right-4 z-[300] flex items-center gap-2 px-3 py-1.5
                        bg-[#0d1421]/95 border border-blue-500/30 rounded-full text-xs text-blue-300
                        shadow-lg shadow-blue-500/10 backdrop-blur-md">
          <Terminal className="w-3 h-3" />
          <span className="w-1.5 h-1.5 bg-blue-400 rounded-full animate-pulse" />
          {activeCount} scan{activeCount > 1 ? 's' : ''} em andamento
        </div>
      )}

      {/* Notifications stack */}
      {notifications.length > 0 && (
        <div className="fixed bottom-6 right-6 z-[400] flex flex-col gap-2 max-w-xs">
          {notifications.map(n => {
            const isError = n.status === 'ERROR';
            const isVuln  = !isError && n.vulnerable === true;
            const isClean = !isError && n.vulnerable === false;
            return (
              <div key={n.id} className={`flex items-center gap-3 px-4 py-3 rounded-xl shadow-2xl border
                                          backdrop-blur-md animate-in slide-in-from-bottom-2 ${
                isError ? 'bg-[#1a0808]/95 border-red-500/30 text-red-200' :
                isVuln  ? 'bg-[#1a0d0d]/95 border-orange-500/30 text-white' :
                          'bg-[#0d1a0d]/95 border-emerald-500/30 text-white'
              }`}>
                <div className={`p-1.5 rounded-lg shrink-0 ${
                  isError ? 'bg-red-500/20' : isVuln ? 'bg-orange-500/20' : 'bg-emerald-500/20'
                }`}>
                  {isError
                    ? <AlertTriangle className="w-4 h-4 text-red-400" />
                    : isVuln
                      ? <AlertTriangle className="w-4 h-4 text-orange-400" />
                      : <CheckCircle className="w-4 h-4 text-emerald-400" />
                  }
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-semibold leading-none">
                    {isError ? 'Scan falhou' : isVuln ? '⚠️ Vulnerabilidades' : '🛡️ Código seguro'}
                  </p>
                  <p className="text-[10px] text-gray-400 mt-1 truncate">{n.repoName}</p>
                  {isError && n.error && (
                    <p className="text-[10px] text-red-400 mt-0.5 truncate">{n.error}</p>
                  )}
                </div>
                <button onClick={() => dismiss(n.id)}
                  className="text-gray-500 hover:text-white transition-colors shrink-0">
                  <X className="w-4 h-4" />
                </button>
              </div>
            );
          })}
        </div>
      )}
    </>
  );
}

// ── Shared nav-item style ─────────────────────────────────────────────────────
const activeClass   = 'bg-blue-600/10 text-blue-400 border border-blue-500/20 shadow-[0_0_15px_rgba(59,130,246,0.15)]';
const inactiveClass = 'text-gray-400 hover:bg-white/5 hover:text-white border border-transparent';
const baseClass     = 'w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-lg transition-all duration-150';

// ── Sub-items for Ativos & Produtos ──────────────────────────────────────────
const assetSubItems = [
  { id: 'repos',      path: '/assets/repositories', label: 'Repositórios',       icon: <GitBranch className="w-3.5 h-3.5" />, hint: 'GitHub · GitLab' },
  { id: 'cloud',      path: '/assets/cloud',        label: 'Cloud',              icon: <Cloud     className="w-3.5 h-3.5" />, hint: 'AWS · Azure · GCP' },
  { id: 'containers', path: '/assets/containers',   label: 'Contêineres',        icon: <Box       className="w-3.5 h-3.5" />, hint: 'Imagens Docker' },
  { id: 'vms',        path: '/assets/vms',          label: 'Máquinas Virtuais',  icon: <Monitor   className="w-3.5 h-3.5" />, hint: 'VMs & Instâncias' },
  { id: 'domains',    path: '/assets/domains',      label: 'Domínios & APIs',    icon: <Globe     className="w-3.5 h-3.5" />, hint: 'Endpoints expostos' },
];

// ── Flat nav items (no sub-menu) ──────────────────────────────────────────────
const mainNavItems = [
  { id: 'overview',  path: '/',           label: 'Visão Geral',          icon: <LayoutDashboard className="w-4 h-4" /> },
  { id: 'pentest',   path: '/pentest',    label: 'Pentest',              icon: <Workflow        className="w-4 h-4" /> },
  { id: 'findings',  path: '/findings',   label: 'Central de Findings',  icon: <TerminalSquare  className="w-4 h-4" /> },
  { id: 'ai',        path: '/ai-insights',label: 'IA Insights',          icon: <BrainCircuit    className="w-4 h-4" /> },
  { id: 'risk',      path: '/risk',       label: 'Métricas de Risco',    icon: <TrendingUp      className="w-4 h-4" /> },
  { id: 'reports',   path: '/reports',    label: 'Relatórios',           icon: <FileText        className="w-4 h-4" /> },
];

const bottomNavItems = [
  { id: 'integrations', path: '/integrations', label: 'Integrações',   icon: <Puzzle   className="w-4 h-4" /> },
  { id: 'settings',     path: '/settings',     label: 'Configurações', icon: <Settings className="w-4 h-4" /> },
];

// ── Simple flat NavItem ───────────────────────────────────────────────────────
function NavItem({ item }) {
  return (
    <NavLink
      to={item.path}
      end={item.path === '/'}
      className={({ isActive }) => `${baseClass} ${isActive ? activeClass : inactiveClass}`}
    >
      {item.icon}
      {item.label}
    </NavLink>
  );
}

// ── Accordion: Ativos & Produtos ──────────────────────────────────────────────
// Comportamento duplo:
//   • Clique no ícone + label  → navega para /assets (resumo geral)
//   • Clique no chevron        → apenas expande/recolhe, sem navegar
function AssetsAccordion() {
  const location  = useLocation();
  const navigate  = useNavigate();

  const isOnAssets = location.pathname.startsWith('/assets');
  const [open, setOpen] = useState(isOnAssets);

  // Chevron: só toggle, sem propagar para o link pai
  const handleChevron = (e) => {
    e.stopPropagation();
    setOpen(o => !o);
  };

  return (
    <div>
      {/* ── Linha pai: duas zonas de clique ─────────────────────────────── */}
      <div
        className={`${baseClass} justify-between pr-1 ${
          isOnAssets ? activeClass : inactiveClass
        }`}
      >
        {/* Zona esquerda — navega para /assets */}
        <button
          onClick={() => navigate('/assets')}
          className="flex items-center gap-3 flex-1 text-left"
          aria-label="Ir para Ativos & Produtos"
        >
          <Server className="w-4 h-4 shrink-0" />
          <span>Ativos &amp; Produtos</span>
        </button>

        {/* Zona direita — só expande/recolhe */}
        <button
          onClick={handleChevron}
          aria-label={open ? 'Recolher sub-menu' : 'Expandir sub-menu'}
          className="p-1 rounded hover:bg-white/10 transition-colors ml-1 shrink-0"
        >
          <ChevronDown
            className="w-3.5 h-3.5 transition-transform duration-250"
            style={{ transform: open ? 'rotate(180deg)' : 'rotate(0deg)' }}
          />
        </button>
      </div>

      {/* ── Sub-lista animada ────────────────────────────────────────────── */}
      <div
        style={{
          maxHeight: open ? `${assetSubItems.length * 52}px` : '0px',
          overflow: 'hidden',
          transition: 'max-height 260ms cubic-bezier(0.4, 0, 0.2, 1)',
        }}
      >
        {/* mb-3 garante espaço antes do próximo item ("Pentest") */}
        <div className="mt-0.5 ml-3 pl-3 border-l border-white/8 space-y-0.5 py-0.5 mb-3">
          {assetSubItems.map(sub => (
            <NavLink
              key={sub.id}
              to={sub.path}
              className={({ isActive }) =>
                `w-full flex items-start gap-2.5 px-2.5 py-1.5 text-xs rounded-md transition-all duration-150 ${
                  isActive
                    ? 'text-blue-400 bg-blue-600/10 border border-blue-500/15'
                    : 'text-gray-500 hover:text-gray-200 hover:bg-white/5 border border-transparent'
                }`
              }
            >
              <span className="mt-[1px] shrink-0">{sub.icon}</span>
              <span className="flex flex-col leading-tight">
                <span className="font-medium">{sub.label}</span>
                <span className="text-[10px] text-gray-600 mt-0.5">{sub.hint}</span>
              </span>
            </NavLink>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Main layout ───────────────────────────────────────────────────────────────
export default function DashboardLayout({ setIsAuthenticated }) {
  const navigate = useNavigate();

  const handleLogout = () => {
    setIsAuthenticated(false);
    navigate('/login');
  };

  return (
    <div className="flex h-screen w-full bg-[#060b13] text-gray-200 overflow-hidden">
      <ScanMonitor />

      {/* ── Sidebar ──────────────────────────────────────────────────────────── */}
      <aside className="w-64 border-r border-white/5 flex flex-col bg-[#060b13]/80 backdrop-blur-xl shrink-0">

        {/* Logo */}
        <div className="p-6 border-b border-white/5 shrink-0">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-6 h-6 text-blue-500" />
            <div>
              <h1 className="text-xl font-bold tracking-tight text-white leading-none">PreviSwit</h1>
              <p className="text-[10px] text-gray-500 font-medium uppercase tracking-widest mt-0.5">ASPM Console</p>
            </div>
          </div>
        </div>

        {/* Main nav — scrollable */}
        <nav className="flex-1 p-3 space-y-0.5 overflow-y-auto">
          <p className="px-3 pt-2 pb-1.5 text-[10px] font-semibold uppercase tracking-widest text-gray-600 select-none">
            Plataforma
          </p>

          {/* Visão Geral */}
          <NavItem item={mainNavItems[0]} />

          {/* Ativos & Produtos — accordion */}
          <AssetsAccordion />

          {/* Remaining main items */}
          {mainNavItems.slice(1).map(item => (
            <NavItem key={item.id} item={item} />
          ))}
        </nav>

        {/* ── Bottom block: Sistema + Logout ───────────────────────────────── */}
        <div className="shrink-0 border-t border-white/5">
          <div className="p-3 space-y-0.5">
            <p className="px-3 pt-1 pb-1.5 text-[10px] font-semibold uppercase tracking-widest text-gray-600 select-none">
              Sistema
            </p>
            {bottomNavItems.map(item => (
              <NavItem key={item.id} item={item} />
            ))}
          </div>

          <div className="p-3 pt-0">
            <button
              onClick={handleLogout}
              className={`${baseClass} text-gray-500 hover:text-red-400 hover:bg-red-500/10`}
            >
              <LogOut className="w-4 h-4" />
              Sair da conta
            </button>
          </div>
        </div>
      </aside>

      {/* ── Main Content ─────────────────────────────────────────────────────── */}
      <main className="flex-1 flex flex-col overflow-hidden relative">
        <div className="absolute top-0 right-0 w-1/2 h-full bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-blue-900/10 via-transparent to-transparent pointer-events-none" />
        <div className="flex-1 overflow-y-auto p-8 relative z-10">
          <Outlet />
        </div>
      </main>

    </div>
  );
}
