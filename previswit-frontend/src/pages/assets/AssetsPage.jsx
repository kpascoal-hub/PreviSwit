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
import { NavLink } from 'react-router-dom';
import {
  GitBranch, Cloud, Box, Monitor, Globe, Server,
  ShieldAlert, Activity, AlertTriangle, CheckCircle, RefreshCw,
} from 'lucide-react';

const API = '/api/v1';

const ICON_MAP = {
  'git-branch': <GitBranch className="w-5 h-5" />,
  'cloud':      <Cloud className="w-5 h-5" />,
  'box':        <Box className="w-5 h-5" />,
  'monitor':    <Monitor className="w-5 h-5" />,
  'globe':      <Globe className="w-5 h-5" />,
};

const COLOR_MAP = {
  purple:  { bg: 'bg-purple-500/10', border: 'border-purple-500/20', text: 'text-purple-400', bar: 'bg-purple-500' },
  sky:     { bg: 'bg-sky-500/10',    border: 'border-sky-500/20',    text: 'text-sky-400',    bar: 'bg-sky-500' },
  cyan:    { bg: 'bg-cyan-500/10',   border: 'border-cyan-500/20',   text: 'text-cyan-400',   bar: 'bg-cyan-500' },
  amber:   { bg: 'bg-amber-500/10',  border: 'border-amber-500/20',  text: 'text-amber-400',  bar: 'bg-amber-500' },
  emerald: { bg: 'bg-emerald-500/10',border: 'border-emerald-500/20',text: 'text-emerald-400',bar: 'bg-emerald-500' },
};

const TYPE_TO_PATH = {
  REPOSITORY: '/assets/repositories',
  CLOUD:      '/assets/cloud',
  CONTAINER:  '/assets/containers',
  VM:         '/assets/vms',
  DOMAIN:     '/assets/domains',
};

const SEV_CONFIG = {
  CRITICAL: { label: 'Crítico',  color: 'bg-rose-500',   text: 'text-rose-400',   border: 'border-rose-500/30' },
  HIGH:     { label: 'Alto',     color: 'bg-orange-500', text: 'text-orange-400', border: 'border-orange-500/30' },
  MEDIUM:   { label: 'Médio',    color: 'bg-amber-500',  text: 'text-amber-400',  border: 'border-amber-500/30' },
  LOW:      { label: 'Baixo',    color: 'bg-blue-500',   text: 'text-blue-400',   border: 'border-blue-500/30' },
};

function RiskScoreBadge({ level }) {
  const map = {
    CRITICAL: 'text-rose-400 bg-rose-500/10 border-rose-500/30',
    HIGH:     'text-orange-400 bg-orange-500/10 border-orange-500/30',
    MEDIUM:   'text-amber-400 bg-amber-500/10 border-amber-500/30',
    LOW:      'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
  };
  return (
    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border uppercase tracking-wide ${map[level] ?? map.LOW}`}>
      {level ?? 'N/A'}
    </span>
  );
}

export default function AssetsPage() {
  const [summary,     setSummary]     = useState(null);
  const [assets,      setAssets]      = useState([]);
  const [risk,        setRisk]        = useState(null);
  const [findings,    setFindings]    = useState([]);
  const [engagements, setEngagements] = useState([]);
  const [loading,     setLoading]     = useState(false);
  const [error,       setError]       = useState(false);

  const fetchData = async () => {
    setLoading(true);
    setError(false);
    try {
      const [sumRes, listRes, riskRes, findRes, engRes] = await Promise.all([
        fetch(`${API}/assets/summary`),
        fetch(`${API}/assets/`),
        fetch(`${API}/risk/score`),
        fetch(`${API}/findings/?page_size=1000`),
        fetch(`${API}/engagements/`),
      ]);

      if (sumRes.ok)  setSummary(await sumRes.json());
      if (listRes.ok) setAssets((await listRes.json()).assets ?? []);
      if (riskRes.ok) setRisk(await riskRes.json());
      if (findRes.ok) setFindings((await findRes.json()).findings ?? []);
      if (engRes.ok)  setEngagements((await engRes.json()).engagements ?? []);
      if (!sumRes.ok && !listRes.ok) setError(true);
    } catch {
      setError(true);
    }
    setLoading(false);
  };

  useEffect(() => { fetchData(); }, []);

  // ── Métricas calculadas ──────────────────────────────────────────────────
  const total    = summary?.total ?? assets.length;
  const critical = summary?.critical ?? 0;

  const openFindings = findings.filter(f =>
    !['closed', 'false_positive'].includes(f.status)
  );
  const sevCount = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  openFindings.forEach(f => {
    const s = (f.severity || 'LOW').toUpperCase();
    if (s in sevCount) sevCount[s]++;
  });
  const totalOpen = openFindings.length;
  const sevTotal  = Object.values(sevCount).reduce((a, b) => a + b, 0) || 1;

  const riskScore = risk?.score ?? 0;
  const riskLevel = risk?.level ?? 'LOW';

  const lastScan = engagements.length > 0
    ? engagements.slice().sort((a, b) =>
        new Date(b.created_at || 0) - new Date(a.created_at || 0)
      )[0]
    : null;

  const activeScans = engagements.filter(e => e.status === 'active' || e.status === 'running').length;

  return (
    <div className="flex flex-col h-full space-y-5">

      {/* ── Header ──────────────────────────────────────────────────────── */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-4">
          <div className="p-3 rounded-xl bg-blue-500/10 border border-blue-500/20">
            <Server className="w-6 h-6 text-blue-400" />
          </div>
          <div>
            <h2 className="text-xl font-semibold text-white">Ativos &amp; Produtos</h2>
            <p className="text-sm text-gray-500 mt-0.5">
              Inventário de ativos digitais consolidado com dados de findings, risco e scans.
            </p>
          </div>
        </div>
        <button
          onClick={fetchData}
          disabled={loading}
          className="flex items-center gap-1.5 text-xs bg-white/5 text-gray-400 border border-white/10 px-3 py-1.5 rounded-lg hover:bg-white/10 hover:text-white transition-all disabled:opacity-50"
        >
          <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
          Atualizar
        </button>
      </div>

      {/* ── KPI strip ───────────────────────────────────────────────────── */}
      <div className="grid grid-cols-3 gap-3">
        {/* Total Ativos */}
        <div className="bg-[#0d1421] border border-white/5 rounded-xl p-5 flex items-center gap-4">
          <Server className="w-8 h-8 text-blue-400/60 shrink-0" />
          <div>
            <p className="text-[11px] text-gray-500 uppercase tracking-wider">Total de Ativos</p>
            <p className="text-3xl font-bold text-white mt-0.5">{loading ? '…' : total}</p>
            {lastScan && (
              <p className="text-[10px] text-gray-600 mt-0.5">
                Último scan: {new Date(lastScan.created_at).toLocaleDateString('pt-BR')}
              </p>
            )}
          </div>
        </div>

        {/* Score de Risco */}
        <div className="bg-[#0d1421] border border-white/5 rounded-xl p-5 flex items-center gap-4">
          <Activity className="w-8 h-8 text-purple-400/60 shrink-0" />
          <div>
            <p className="text-[11px] text-gray-500 uppercase tracking-wider">Score de Risco</p>
            <div className="flex items-baseline gap-2 mt-0.5">
              <p className="text-3xl font-bold text-white">{loading ? '…' : riskScore}</p>
              {!loading && <span className="text-sm text-gray-500">/100</span>}
            </div>
            {!loading && <RiskScoreBadge level={riskLevel} />}
          </div>
        </div>

        {/* Findings Abertos */}
        <div className="bg-[#0d1421] border border-white/5 rounded-xl p-5 flex items-center gap-4">
          <ShieldAlert className="w-8 h-8 text-red-400/60 shrink-0" />
          <div>
            <p className="text-[11px] text-gray-500 uppercase tracking-wider">Findings Abertos</p>
            <p className="text-3xl font-bold text-white mt-0.5">{loading ? '…' : totalOpen}</p>
            {!loading && critical > 0 && (
              <p className="text-[10px] text-rose-400 mt-0.5">{critical} crítico{critical > 1 ? 's' : ''}</p>
            )}
          </div>
        </div>
      </div>

      {/* ── Distribuição de Severidade ───────────────────────────────────── */}
      {!loading && totalOpen > 0 && (
        <div className="bg-[#0d1421] border border-white/5 rounded-xl p-4">
          <p className="text-[11px] text-gray-500 uppercase tracking-wider mb-3">
            Distribuição de Findings por Severidade
          </p>
          {/* Barra proporcional */}
          <div className="flex h-2 rounded-full overflow-hidden gap-0.5 mb-3">
            {Object.entries(SEV_CONFIG).map(([sev, cfg]) => {
              const pct = (sevCount[sev] / sevTotal) * 100;
              return pct > 0 ? (
                <div
                  key={sev}
                  className={`${cfg.color} transition-all`}
                  style={{ width: `${pct}%` }}
                  title={`${sev}: ${sevCount[sev]}`}
                />
              ) : null;
            })}
          </div>
          {/* Legenda */}
          <div className="flex flex-wrap gap-4">
            {Object.entries(SEV_CONFIG).map(([sev, cfg]) => (
              <div key={sev} className="flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${cfg.color}`} />
                <span className="text-[11px] text-gray-400">{cfg.label}</span>
                <span className={`text-[11px] font-bold ${sevCount[sev] > 0 ? cfg.text : 'text-gray-600'}`}>
                  {sevCount[sev]}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Categoria cards ──────────────────────────────────────────────── */}
      <div>
        <p className="text-xs font-semibold uppercase tracking-widest text-gray-600 mb-3">
          Explorar por Categoria
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
          {summary
            ? Object.entries(summary.by_type).map(([typeKey, cat]) => {
                const colors = COLOR_MAP[cat.color] ?? COLOR_MAP.purple;
                const icon   = ICON_MAP[cat.icon] ?? <Server className="w-5 h-5" />;
                const path   = TYPE_TO_PATH[typeKey] ?? '/assets';
                const hasCritical = cat.critical > 0 || cat.high > 0;
                return (
                  <NavLink
                    key={typeKey}
                    to={path}
                    className="group flex items-center gap-4 p-4 bg-[#0d1421] border border-white/5 rounded-xl hover:border-white/10 hover:bg-[#111b2e] transition-all duration-150"
                  >
                    <div className={`p-2.5 rounded-lg border ${colors.bg} ${colors.border} shrink-0`}>
                      <span className={colors.text}>{icon}</span>
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-semibold text-white group-hover:text-gray-100">{cat.label}</p>
                      <p className="text-[11px] text-gray-500 mt-0.5">{cat.hint}</p>
                    </div>
                    <div className="shrink-0 text-right">
                      <p className={`text-lg font-bold ${colors.text}`}>{cat.count}</p>
                      {hasCritical ? (
                        <p className="text-[10px] text-rose-400 flex items-center justify-end gap-1">
                          <AlertTriangle className="w-2.5 h-2.5" />
                          {cat.critical > 0 ? `${cat.critical} crítico${cat.critical > 1 ? 's' : ''}` : `${cat.high} alto${cat.high > 1 ? 's' : ''}`}
                        </p>
                      ) : (
                        <p className="text-[10px] text-gray-600 flex items-center justify-end gap-1">
                          <CheckCircle className="w-2.5 h-2.5 text-emerald-600" />
                          sem críticos
                        </p>
                      )}
                    </div>
                  </NavLink>
                );
              })
            : Array.from({ length: 5 }).map((_, i) => (
                <div key={i} className="h-[76px] bg-[#0d1421] border border-white/5 rounded-xl animate-pulse" />
              ))
          }
        </div>
      </div>

      {/* ── Atividade de Engajamentos ────────────────────────────────────── */}
      {!loading && engagements.length > 0 && (
        <div className="bg-[#0d1421] border border-white/5 rounded-xl p-4">
          <div className="flex items-center justify-between mb-3">
            <p className="text-[11px] text-gray-500 uppercase tracking-wider">Atividade de Scans</p>
            {activeScans > 0 && (
              <span className="flex items-center gap-1 text-[10px] text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 rounded-full">
                <span className="w-1.5 h-1.5 bg-emerald-400 rounded-full animate-pulse" />
                {activeScans} ativo{activeScans > 1 ? 's' : ''}
              </span>
            )}
          </div>
          <div className="flex flex-wrap gap-3">
            {engagements.slice(0, 6).map((eng, i) => (
              <div key={i} className="flex items-center gap-2 bg-white/3 border border-white/5 rounded-lg px-3 py-2">
                <div className={`w-1.5 h-1.5 rounded-full ${
                  eng.status === 'active' || eng.status === 'running' ? 'bg-emerald-400 animate-pulse' :
                  eng.status === 'completed' ? 'bg-blue-400' : 'bg-gray-600'
                }`} />
                <p className="text-[11px] text-gray-300 font-medium truncate max-w-[140px]">
                  {eng.name || eng.target || `Scan #${i + 1}`}
                </p>
                <p className="text-[10px] text-gray-600">
                  {eng.created_at ? new Date(eng.created_at).toLocaleDateString('pt-BR') : '—'}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Inventário completo ──────────────────────────────────────────── */}
      <div className="flex-1 min-h-0 flex flex-col bg-[#0d1421] border border-white/5 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-white/5 flex items-center justify-between shrink-0">
          <div>
            <p className="text-sm font-semibold text-gray-300">Inventário Completo</p>
            <p className="text-[11px] text-gray-600 mt-0.5">Ativos descobertos a partir dos findings e integrações</p>
          </div>
          <span className="text-xs px-2 py-1 bg-white/5 border border-white/10 rounded-full text-gray-400">
            {loading ? '…' : `${total} ativo${total !== 1 ? 's' : ''}`}
          </span>
        </div>

        <div className="p-4 overflow-y-auto flex-1">
          {loading && (
            <div className="flex flex-col items-center justify-center py-16 gap-3">
              <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
              <p className="text-sm text-gray-500">Carregando ativos…</p>
            </div>
          )}
          {error && !loading && (
            <p className="text-red-400 text-sm text-center py-12">Erro ao conectar com a API.</p>
          )}
          {!loading && !error && assets.length === 0 && (
            <div className="flex flex-col items-center justify-center py-16 gap-3">
              <div className="p-4 rounded-xl bg-white/3 border border-white/5">
                <Server className="w-8 h-8 text-gray-600" />
              </div>
              <p className="text-sm text-gray-600">Nenhum ativo detectado ainda.</p>
              <p className="text-xs text-gray-700">Execute um scan para descobrir ativos automaticamente.</p>
            </div>
          )}
          {!loading && !error && assets.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-white/5 bg-[#111827]/60">
                    <th className="py-3 px-4 text-[11px] font-bold text-gray-400 uppercase tracking-wider">Ativo</th>
                    <th className="py-3 px-4 text-[11px] font-bold text-gray-400 uppercase tracking-wider">Tipo</th>
                    <th className="py-3 px-4 text-[11px] font-bold text-gray-400 uppercase tracking-wider">Findings</th>
                    <th className="py-3 px-4 text-[11px] font-bold text-gray-400 uppercase tracking-wider">Criticidade</th>
                    <th className="py-3 px-4 text-[11px] font-bold text-gray-400 uppercase tracking-wider">Última Atividade</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {assets.map((a, i) => {
                    const typeMeta = {
                      REPOSITORY: { label: 'Repositório', color: COLOR_MAP.purple, icon: ICON_MAP['git-branch'] },
                      CLOUD:      { label: 'Cloud',       color: COLOR_MAP.sky,    icon: ICON_MAP['cloud'] },
                      CONTAINER:  { label: 'Contêiner',   color: COLOR_MAP.cyan,   icon: ICON_MAP['box'] },
                      VM:         { label: 'VM',          color: COLOR_MAP.amber,  icon: ICON_MAP['monitor'] },
                      DOMAIN:     { label: 'Web/API',     color: COLOR_MAP.emerald,icon: ICON_MAP['globe'] },
                    }[a.asset_type] ?? { label: a.asset_type, color: COLOR_MAP.purple, icon: <Server className="w-4 h-4" /> };

                    const critColor =
                      a.criticality === 'CRITICAL' ? 'bg-rose-500/10 text-rose-400 border-rose-500/25' :
                      a.criticality === 'HIGH'     ? 'bg-orange-500/10 text-orange-400 border-orange-500/25' :
                      a.criticality === 'MEDIUM'   ? 'bg-amber-500/10 text-amber-400 border-amber-500/25' :
                                                     'bg-blue-500/10 text-blue-400 border-blue-500/25';

                    return (
                      <tr key={i} className="hover:bg-white/[0.02] transition-colors group">
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-3">
                            <div className={`p-1.5 rounded-lg border ${typeMeta.color.bg} ${typeMeta.color.border} shrink-0`}>
                              <span className={typeMeta.color.text}>{typeMeta.icon}</span>
                            </div>
                            <div>
                              <p className="text-sm font-bold text-white group-hover:text-blue-400 transition-colors">{a.name}</p>
                              {a.host && <p className="text-[10px] text-gray-600 mt-0.5">{a.host}</p>}
                            </div>
                          </div>
                        </td>
                        <td className="py-3 px-4">
                          <span className="text-[11px] font-medium text-gray-300 bg-white/5 px-2 py-0.5 rounded-md border border-white/10">
                            {typeMeta.label}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <span className="text-sm font-bold text-white">{a.total_vulnerabilities || 0}</span>
                          {a.findings_count?.critical > 0 && (
                            <span className="ml-2 text-[10px] text-rose-400">+{a.findings_count.critical} crítico{a.findings_count.critical > 1 ? 's' : ''}</span>
                          )}
                        </td>
                        <td className="py-3 px-4">
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border uppercase tracking-wide ${critColor}`}>
                            {a.criticality || 'LOW'}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <p className="text-xs text-gray-500">
                            {a.last_seen
                              ? new Date(a.last_seen).toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'short' })
                              : '—'}
                          </p>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

    </div>
  );
}
