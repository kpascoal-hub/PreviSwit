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
 * PreviSwit AI-ASPM — Dashboard Overview (Fixo)
 * =========================================
 * Painel executivo estruturado para rápida tomada de decisão (C-Level).
 * Grid fixo (CSS Grid), consumindo APIs reais e mantendo design Cyber Dark Enterprise.
 */

import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  Shield, AlertTriangle, Server, Zap, Activity,
  Globe, Flame, ShieldAlert, ArrowRight
} from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from 'recharts';

const API = '/api/v1';

// ── Helpers ────────────────────────────────────────────────────────────────────

function getScoreColor(score) {
  if (score >= 85) return { text: 'text-emerald-400', bar: 'bg-emerald-500', glow: 'shadow-emerald-500/20', label: 'Excelente' };
  if (score >= 65) return { text: 'text-amber-400',   bar: 'bg-amber-500',   glow: 'shadow-amber-500/20',   label: 'Moderado'  };
  return              { text: 'text-rose-400',         bar: 'bg-rose-500',    glow: 'shadow-rose-500/20',    label: 'Crítico'   };
}

function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'short' });
}

function Skeleton({ className = '' }) {
  return <div className={`animate-pulse bg-white/5 rounded-lg ${className}`} />;
}

const AI_TIPS = [
  { tip: 'Ative o SAST no pipeline CI/CD para bloquear vulnerabilidades antes do merge.', icon: '🔒' },
  { tip: 'Rotacione secrets automaticamente a cada 90 dias com ferramentas dedicadas.', icon: '🔑' },
  { tip: 'Aplique o princípio do menor privilégio (PoLP) nas policies IAM da sua Cloud.', icon: '☁️' },
  { tip: 'Utilize imagens base distroless nos contêineres para reduzir superfície de ataque.', icon: '📦' },
  { tip: 'Habilite MFA mandatório. Reduz expressivamente ataques de Account Takeover.', icon: '🛡️' },
  { tip: 'Configure Drift Detection para alertar mudanças manuais em recursos providos por IaC.', icon: '⚡' },
];

// ════════════════════════════════════════════════════════════════════════════
//  PAGE
// ════════════════════════════════════════════════════════════════════════════

export default function DashboardPage() {
  const [loading, setLoading]           = useState(true);
  const [findings, setFindings]         = useState([]);
  const [counts, setCounts]             = useState(null);
  const [assetsSummary, setAssets]      = useState(null);
  const [score, setScore]               = useState(null);
  const [chartData, setChartData]       = useState([]);
  const [aiTip]                         = useState(() => AI_TIPS[Math.floor(Math.random() * AI_TIPS.length)]);
  
  const isMounted = useRef(true);

  const fetchAll = async () => {
    setLoading(true);
    try {
      const [findRes, statsRes, assetsRes] = await Promise.allSettled([
        fetch(`${API}/findings/?page_size=50`), // Buscamos mais para a tabela e gráfico se necessário
        fetch(`${API}/findings/stats/summary`),
        fetch(`${API}/assets/summary`),
      ]);

      let loadedFindings = [];
      if (findRes.status === 'fulfilled' && findRes.value.ok) {
        const d = await findRes.value.json();
        loadedFindings = d.findings ?? [];
        if (isMounted.current) setFindings(loadedFindings);
      }
      if (statsRes.status === 'fulfilled' && statsRes.value.ok) {
        const d = await statsRes.value.json();
        if (isMounted.current) {
          const c = d.by_severity ?? d.counts ?? {};
          setCounts(c);
          const s = Math.max(0, 100 - (c.CRITICAL ?? 0) * 15 - (c.HIGH ?? 0) * 5 - (c.MEDIUM ?? 0) * 2);
          setScore(s);
          
          // Gera mock evolutivo baseado no score atual para demonstração visual rica (já que não temos /history real ainda)
          const history = Array.from({ length: 7 }).map((_, i) => {
            const day = new Date();
            day.setDate(day.getDate() - (6 - i));
            // Simula flutuação
            const variation = (Math.random() * 10) - 5;
            return {
              date: day.toLocaleDateString('pt-BR', { weekday: 'short' }),
              score: Math.min(100, Math.max(0, Math.round(s + (i === 6 ? 0 : variation)))),
              critical: Math.max(0, Math.round((c.CRITICAL ?? 0) + (Math.random() * 2 - 1))),
            };
          });
          setChartData(history);
        }
      }
      if (assetsRes.status === 'fulfilled' && assetsRes.value.ok) {
        const d = await assetsRes.value.json();
        if (isMounted.current) setAssets(d);
      }
    } catch (_) {}
    if (isMounted.current) setLoading(false);
  };

  useEffect(() => {
    isMounted.current = true;
    fetchAll();
    return () => { isMounted.current = false; };
  }, []);

  const topFindings = useMemo(() => {
    const sorted = [...findings].sort((a, b) => {
      const w = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
      return (w[b.severity] || 0) - (w[a.severity] || 0);
    });
    return sorted.slice(0, 5);
  }, [findings]);

  const sc = getScoreColor(score ?? 100);
  const totalAssets = assetsSummary?.total ?? 0;
  const criticalThreats = counts?.CRITICAL ?? 0;

  return (
    <div className="flex flex-col gap-6 w-full pb-10">

      {/* ── Header ──────────────────────────────────────────────────────────── */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2.5">
            <Activity className="w-5 h-5 text-blue-400" />
            Visão Geral
          </h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Painel Executivo de Risco &amp; Conformidade (C-Level)
          </p>
        </div>
      </div>

      {/* ── Grid Principal ──────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">

        {/* ── LINHA 1: KPIs Rápidos (3 colunas iguais) ──────────────────────── */}
        
        {/* KPI 1: Score de Risco */}
        <div className="col-span-1 bg-[#060b13]/80 border border-[#1e293b] rounded-2xl p-6 relative overflow-hidden group">
          <div className="absolute top-0 right-0 w-32 h-32 bg-white/5 rounded-full blur-3xl -translate-y-1/2 translate-x-1/2 group-hover:bg-white/10 transition-all" />
          <div className="flex items-center gap-2 text-gray-400 mb-4 relative z-10">
            <Shield className={`w-4 h-4 ${sc.text}`} />
            <span className="text-[11px] uppercase tracking-widest font-semibold">Score de Risco</span>
          </div>
          <div className="relative z-10">
            {loading ? <Skeleton className="w-24 h-12" /> : (
              <div className="flex items-baseline gap-3">
                <span className={`text-5xl font-black ${sc.text}`}>{score ?? 100}</span>
                <span className={`text-sm font-bold ${sc.text}`}>{sc.label}</span>
              </div>
            )}
            <div className="mt-4 w-full h-1.5 bg-white/5 rounded-full overflow-hidden">
              <div className={`h-full rounded-full ${sc.bar}`} style={{ width: `${score ?? 100}%` }} />
            </div>
          </div>
        </div>

        {/* KPI 2: Total de Ativos */}
        <div className="col-span-1 bg-[#060b13]/80 border border-[#1e293b] rounded-2xl p-6 relative overflow-hidden group">
           <div className="absolute top-0 right-0 w-32 h-32 bg-sky-500/5 rounded-full blur-3xl -translate-y-1/2 translate-x-1/2 group-hover:bg-sky-500/10 transition-all" />
          <div className="flex items-center gap-2 text-gray-400 mb-4 relative z-10">
            <Server className="w-4 h-4 text-sky-400" />
            <span className="text-[11px] uppercase tracking-widest font-semibold">Total de Ativos</span>
          </div>
          <div className="relative z-10">
            {loading ? <Skeleton className="w-24 h-12" /> : (
              <div className="flex items-baseline gap-3">
                <span className="text-5xl font-black text-white">{totalAssets}</span>
              </div>
            )}
            <p className="mt-4 text-xs text-gray-500 flex items-center gap-1.5">
              <Globe className="w-3.5 h-3.5" /> Monitorados continuamente
            </p>
          </div>
        </div>

        {/* KPI 3: Ameaças Críticas */}
        <div className="col-span-1 bg-[#060b13]/80 border border-[#1e293b] rounded-2xl p-6 relative overflow-hidden group">
           <div className="absolute top-0 right-0 w-32 h-32 bg-rose-500/5 rounded-full blur-3xl -translate-y-1/2 translate-x-1/2 group-hover:bg-rose-500/10 transition-all" />
          <div className="flex items-center gap-2 text-gray-400 mb-4 relative z-10">
            <ShieldAlert className="w-4 h-4 text-rose-500" />
            <span className="text-[11px] uppercase tracking-widest font-semibold">Ameaças Críticas</span>
          </div>
          <div className="relative z-10">
            {loading ? <Skeleton className="w-24 h-12" /> : (
              <div className="flex items-baseline gap-3">
                <span className="text-5xl font-black text-rose-500">{criticalThreats}</span>
                <span className="text-sm font-bold text-rose-500/70">Ativas</span>
              </div>
            )}
            <p className="mt-4 text-xs text-rose-500/70 flex items-center gap-1.5">
              <Flame className="w-3.5 h-3.5" /> Requerem atenção imediata
            </p>
          </div>
        </div>

        {/* ── LINHA 2: Contexto (Gráfico 2:1 IA) ────────────────────────────── */}
        
        {/* Gráfico Evolutivo de Risco (Largo) */}
        <div className="col-span-1 md:col-span-2 bg-[#060b13]/80 border border-[#1e293b] rounded-2xl p-6 flex flex-col min-h-[300px]">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-sm font-bold text-gray-200">Evolução do Risco (Últimos 7 dias)</h2>
            <span className="text-[10px] text-gray-500 border border-[#1e293b] px-2 py-1 rounded">MOCK DATA</span>
          </div>
          <div className="flex-1 w-full h-full min-h-[200px]">
            {loading ? (
              <div className="w-full h-full flex items-end justify-between gap-2 opacity-20">
                {Array.from({length: 7}).map((_, i) => <div key={i} className="w-full bg-white/10 rounded-t-sm" style={{height: `${Math.random() * 60 + 20}%`}} />)}
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData} margin={{ top: 5, right: 0, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                  <XAxis dataKey="date" stroke="#475569" fontSize={10} tickLine={false} axisLine={false} />
                  <YAxis stroke="#475569" fontSize={10} tickLine={false} axisLine={false} domain={[0, 100]} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', borderRadius: '8px', fontSize: '12px' }}
                    itemStyle={{ color: '#e2e8f0' }}
                  />
                  <Area type="monotone" dataKey="score" name="Health Score" stroke="#3b82f6" strokeWidth={2} fillOpacity={1} fill="url(#colorScore)" />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Último Insight da IA (Lateral) */}
        <div className="col-span-1 bg-gradient-to-b from-[#0f172a]/80 to-[#060b13]/80 border border-[#1e293b] rounded-2xl p-6 flex flex-col relative overflow-hidden group">
          <div className="absolute top-0 right-0 w-32 h-32 bg-violet-500/10 rounded-full blur-3xl -translate-y-1/2 translate-x-1/2" />
          <div className="flex items-center gap-2 text-violet-400 mb-6 relative z-10">
            <Zap className="w-4 h-4 fill-violet-400/20" />
            <span className="text-[11px] uppercase tracking-widest font-bold">Insight IA (Gemini)</span>
          </div>
          <div className="flex-1 flex flex-col justify-center relative z-10">
            <p className="text-3xl mb-4">{aiTip.icon}</p>
            <p className="text-sm text-gray-300 leading-relaxed font-medium">
              {aiTip.tip}
            </p>
          </div>
          <button className="mt-6 flex items-center gap-2 text-xs font-semibold text-violet-400 hover:text-violet-300 transition-colors w-fit relative z-10 group-hover:gap-3">
            Explorar Recomendações <ArrowRight className="w-3 h-3" />
          </button>
        </div>

        {/* ── LINHA 3: Ação (Largura Total) ─────────────────────────────────── */}
        
        {/* Top 5 Riscos Iminentes */}
        <div className="col-span-1 md:col-span-3 bg-[#060b13]/80 border border-[#1e293b] rounded-2xl overflow-hidden">
          <div className="p-5 border-b border-[#1e293b] flex items-center justify-between">
            <h2 className="text-sm font-bold text-gray-200 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-orange-500" />
              Top Riscos Iminentes
            </h2>
            <span className="text-[10px] text-gray-500">Priorização automática por severidade</span>
          </div>
          
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-white/[0.02]">
                  <th className="py-3 px-5 text-[11px] font-semibold text-gray-500 uppercase">Vulnerabilidade</th>
                  <th className="py-3 px-5 text-[11px] font-semibold text-gray-500 uppercase">Ativo Afetado</th>
                  <th className="py-3 px-5 text-[11px] font-semibold text-gray-500 uppercase">Ferramenta</th>
                  <th className="py-3 px-5 text-[11px] font-semibold text-gray-500 uppercase">Severidade</th>
                  <th className="py-3 px-5 text-[11px] font-semibold text-gray-500 uppercase text-right">Descoberto</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e293b]">
                {loading ? (
                  Array.from({length: 3}).map((_, i) => (
                    <tr key={i}>
                      <td className="py-4 px-5"><Skeleton className="h-4 w-48" /></td>
                      <td className="py-4 px-5"><Skeleton className="h-4 w-32" /></td>
                      <td className="py-4 px-5"><Skeleton className="h-4 w-24" /></td>
                      <td className="py-4 px-5"><Skeleton className="h-6 w-16 rounded-full" /></td>
                      <td className="py-4 px-5 flex justify-end"><Skeleton className="h-4 w-20" /></td>
                    </tr>
                  ))
                ) : topFindings.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-sm text-gray-500">Nenhum risco detectado. Você está seguro!</td>
                  </tr>
                ) : (
                  topFindings.map((f, i) => (
                    <tr key={i} className="hover:bg-white/[0.02] transition-colors">
                      <td className="py-3 px-5">
                        <p className="text-sm font-medium text-gray-200 line-clamp-1" title={f.title}>{f.title}</p>
                      </td>
                      <td className="py-3 px-5">
                        <span className="text-xs text-gray-400 font-mono bg-white/5 px-2 py-1 rounded">{f.asset_id || 'N/A'}</span>
                      </td>
                      <td className="py-3 px-5">
                        <span className="text-xs text-gray-500">{f.tool || 'N/A'}</span>
                      </td>
                      <td className="py-3 px-5">
                        <span className={`text-[10px] font-bold px-2.5 py-1 rounded-full border tracking-wide uppercase ${
                          f.severity === 'CRITICAL' ? 'bg-rose-500/10 text-rose-400 border-rose-500/25' :
                          f.severity === 'HIGH' ? 'bg-orange-500/10 text-orange-400 border-orange-500/25' :
                          f.severity === 'MEDIUM' ? 'bg-amber-500/10 text-amber-400 border-amber-500/25' :
                          'bg-blue-500/10 text-blue-400 border-blue-500/25'
                        }`}>
                          {f.severity}
                        </span>
                      </td>
                      <td className="py-3 px-5 text-right">
                        <span className="text-xs text-gray-500">{fmtDate(f.created_at)}</span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

      </div>
    </div>
  );
}


