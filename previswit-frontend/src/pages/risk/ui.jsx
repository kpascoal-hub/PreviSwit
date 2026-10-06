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
 * PreviSwit AI-ASPM — Métricas de Risco: primitivas de UI
 * ========================================================
 * Compartilhado pelas 4 abas do painel. Segue o design system estabelecido
 * nas páginas irmãs (Cyber Dark Enterprise), sem inventar convenção nova.
 */

import React from 'react';
import { AlertTriangle, Info } from 'lucide-react';

// ── Convenção de sinal ────────────────────────────────────────────────────────
// A API usa 0 = melhor, 100 = pior. Exibimos essa convenção diretamente e
// chamamos o número de "Risco" (não de "Health Score"), porque inverter para
// exibição é a fonte de bug mais provável desta tela.

export function riskColors(score) {
  if (score >= 75) return { text: 'text-rose-400',    bg: 'bg-rose-500/10',    border: 'border-rose-500/25',    dot: 'bg-rose-500',    bar: 'bg-rose-500',    glow: 'drop-shadow-[0_0_12px_rgba(244,63,94,0.45)]' };
  if (score >= 50) return { text: 'text-red-400',     bg: 'bg-red-500/10',     border: 'border-red-500/25',     dot: 'bg-red-500',     bar: 'bg-red-500',     glow: 'drop-shadow-[0_0_12px_rgba(239,68,68,0.40)]' };
  if (score >= 25) return { text: 'text-amber-400',   bg: 'bg-amber-500/10',   border: 'border-amber-500/25',   dot: 'bg-amber-500',   bar: 'bg-amber-500',   glow: 'drop-shadow-[0_0_12px_rgba(245,158,11,0.35)]' };
  return              { text: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/25', dot: 'bg-emerald-500', bar: 'bg-emerald-500', glow: 'drop-shadow-[0_0_12px_rgba(52,211,153,0.35)]' };
}

/** Conformidade: aqui é o contrário — alto é bom. */
export function complianceColors(pct) {
  if (pct >= 90) return { text: 'text-emerald-400', bar: 'bg-emerald-500', border: 'border-emerald-500/25', bg: 'bg-emerald-500/10' };
  if (pct >= 70) return { text: 'text-lime-400',    bar: 'bg-lime-500',    border: 'border-lime-500/25',    bg: 'bg-lime-500/10' };
  if (pct >= 40) return { text: 'text-amber-400',   bar: 'bg-amber-500',   border: 'border-amber-500/25',   bg: 'bg-amber-500/10' };
  return             { text: 'text-rose-400',    bar: 'bg-rose-500',    border: 'border-rose-500/25',    bg: 'bg-rose-500/10' };
}

export function sevColors(sev) {
  const s = (sev || '').toUpperCase();
  if (s === 'CRITICAL') return { text: 'text-rose-400',  bg: 'bg-rose-500/10',  border: 'border-rose-500/25',  dot: 'bg-rose-500' };
  if (s === 'HIGH')     return { text: 'text-red-400',   bg: 'bg-red-500/10',   border: 'border-red-500/25',   dot: 'bg-red-500' };
  if (s === 'MEDIUM')   return { text: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/25', dot: 'bg-amber-500' };
  if (s === 'LOW')      return { text: 'text-blue-400',  bg: 'bg-blue-500/10',  border: 'border-blue-500/25',  dot: 'bg-blue-500' };
  return                    { text: 'text-gray-400',  bg: 'bg-gray-500/10',  border: 'border-gray-500/25',  dot: 'bg-gray-500' };
}

export function money(obj, currency) {
  if (!obj) return '—';
  const v = currency === 'USD' ? obj.usd : obj.brl;
  if (v == null) return '—';
  return currency === 'USD'
    ? `$ ${v.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`
    : `R$ ${v.toLocaleString('pt-BR', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
}

// ── Primitivas ────────────────────────────────────────────────────────────────

export function Panel({ title, icon, accent = 'from-emerald-500/50 to-teal-500/25', right, children, className = '' }) {
  return (
    <div className={`rounded-2xl border border-white/[0.06] bg-gradient-to-b from-[#0d1421]/80 to-[#060b13]/60 overflow-hidden ${className}`}>
      <div className={`h-[2px] w-full bg-gradient-to-r ${accent}`} />
      {title && (
        <div className="flex items-center justify-between gap-3 px-5 py-3.5 border-b border-white/[0.05] bg-[#060b13]/60">
          <div className="flex items-center gap-2 min-w-0">
            {icon}
            <span className="text-sm font-bold text-white truncate">{title}</span>
          </div>
          {right}
        </div>
      )}
      {children}
    </div>
  );
}

export function Bar({ pct, className = 'bg-emerald-500', height = 'h-2' }) {
  return (
    <div className={`w-full ${height} rounded-full bg-white/[0.05] overflow-hidden`}>
      <div
        className={`h-full rounded-full transition-all duration-700 ${className}`}
        style={{ width: `${Math.max(0, Math.min(100, pct || 0))}%` }}
      />
    </div>
  );
}

export function SevBadge({ sev }) {
  const c = sevColors(sev);
  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full border text-[10px] font-bold tracking-wide ${c.bg} ${c.text} ${c.border}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${c.dot}`} />
      {(sev || 'N/A').toUpperCase()}
    </span>
  );
}

/** Rodapé de honestidade. Aparece sempre que um percentual é exibido. */
export function ScopeNote({ children }) {
  return (
    <p className="text-[10px] text-gray-600 leading-relaxed flex items-start gap-1.5">
      <Info className="w-3 h-3 shrink-0 mt-px" />
      <span>{children}</span>
    </p>
  );
}

export function EmptyState({ icon, title, subtitle }) {
  return (
    <div className="flex flex-col items-center justify-center py-14 gap-3 px-6 text-center">
      <div className="w-12 h-12 rounded-2xl bg-white/[0.04] border border-white/[0.07] flex items-center justify-center">
        {icon}
      </div>
      <p className="text-sm font-semibold text-gray-300">{title}</p>
      {subtitle && <p className="text-xs text-gray-600 max-w-sm leading-relaxed">{subtitle}</p>}
    </div>
  );
}

export function Spinner({ label }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 gap-3">
      <div className="relative">
        <div className="w-9 h-9 border-2 border-emerald-500/25 rounded-full" />
        <div className="w-9 h-9 border-2 border-emerald-500 border-t-transparent rounded-full animate-spin absolute inset-0" />
      </div>
      {label && <p className="text-xs text-gray-500">{label}</p>}
    </div>
  );
}

export function ErrorBanner({ message }) {
  return (
    <div className="flex items-center gap-3 px-4 py-3 rounded-xl bg-rose-500/5 border border-rose-500/20 text-xs text-rose-400">
      <AlertTriangle className="w-4 h-4 shrink-0" />
      <span>{message}</span>
    </div>
  );
}

export const API = '/api/v1';

/** Fetch com erro legível. Nunca deixa a aba num estado ambíguo. */
export async function jget(path) {
  const res = await fetch(`${API}${path}`);
  if (!res.ok) throw new Error(`HTTP ${res.status} em ${path}`);
  return res.json();
}
