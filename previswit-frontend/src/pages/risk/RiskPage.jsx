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
 * PreviSwit AI-ASPM — Métricas de Risco & Governança
 * ===================================================
 * Cockpit executivo: postura de risco, conformidade em 7 frameworks,
 * radar de ameaças e regulatório, plano de ação e simulador de investimento.
 *
 * TUDO vem da API (`/api/v1/posture/*`). Zero localStorage, zero número
 * inventado no cliente. A versão anterior desta página semeava histórico
 * falso em localStorage e estimava exposição financeira como
 * `CRITICAL * 50000` — ambos removidos.
 *
 * CONVENÇÃO DE SINAL: a API usa 0 = melhor, 100 = pior. Exibimos exatamente
 * essa convenção e chamamos o número de "Risco" (não "Health Score"), porque
 * inverter para exibição é a fonte de bug mais provável desta tela.
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts';
import {
  Activity, ShieldCheck, Radar, ClipboardList, Calculator,
  RefreshCw, TrendingUp, TrendingDown, Minus, AlertTriangle,
  CheckCircle, XCircle, Layers, ShieldAlert,
} from 'lucide-react';

import { Panel, Bar, riskColors, ScopeNote, Spinner, ErrorBanner, jget, API } from './ui';
import ComplianceTab from './tabs/ComplianceTab';
import RadarTab from './tabs/RadarTab';
import ActionPlanTab from './tabs/ActionPlanTab';
import SimulatorTab from './tabs/SimulatorTab';

const TABS = [
  { id: 'compliance', label: 'Conformidade', icon: ShieldCheck },
  { id: 'simulator',  label: 'Simulador',    icon: Calculator },
  { id: 'radar',      label: 'Radar',        icon: Radar },
  { id: 'plan',       label: 'Plano de Ação', icon: ClipboardList },
];

const TREND = {
  improving: { icon: TrendingDown, text: 'text-emerald-400', label: 'melhorando' },
  worsening: { icon: TrendingUp,   text: 'text-rose-400',    label: 'piorando' },
  stable:    { icon: Minus,        text: 'text-gray-500',    label: 'estável' },
};

/** Gradiente com id próprio — `colorScore` já é usado pelo DashboardPage. */
const GRADIENT_ID = 'riskPostureGradient';

const HistoryTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  const v = payload[0].value;
  const c = riskColors(v);
  return (
    <div className="bg-[#060b13]/95 border border-white/[0.08] p-3 rounded-xl shadow-xl backdrop-blur-md">
      <p className="text-[10px] text-gray-500 uppercase tracking-wider font-bold mb-1">{label}</p>
      <div className="flex items-center gap-2">
        <div className={`w-2 h-2 rounded-full ${c.dot}`} />
        <p className="text-sm font-black text-white">
          Risco <span className={c.text}>{v}</span>
        </p>
      </div>
    </div>
  );
};

export default function RiskPage() {
  const [tab, setTab] = useState('compliance');
  const [currency, setCurrency] = useState('BRL');

  const [snapshot, setSnapshot] = useState(null);
  const [history, setHistory] = useState([]);
  const [historyNote, setHistoryNote] = useState(null);
  const [compliance, setCompliance] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [toast, setToast] = useState(null);

  const showToast = useCallback((type, msg) => {
    setToast({ type, msg });
    setTimeout(() => setToast(null), 4000);
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      // Grava o snapshot do dia (upsert idempotente) antes de ler o histórico,
      // para o gráfico já incluir o ponto de hoje.
      fetch(`${API}/posture/snapshot/record`, { method: 'POST' }).catch(() => {});

      const [snap, hist, comp] = await Promise.all([
        jget('/posture/snapshot'),
        jget('/posture/history?days=30&bucket=day'),
        jget('/posture/compliance'),
      ]);
      setSnapshot(snap);
      setHistory((hist.history || []).map(h => ({
        date: h.date_label || String(h.recorded_at || '').slice(0, 10),
        score: h.score,
      })));
      setHistoryNote(hist.legacy_note || null);
      setCompliance(comp);
    } catch (e) {
      setError(`Falha ao carregar postura: ${e.message}`);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const score = snapshot?.risk_score ?? 0;
  const c = riskColors(score);
  const trend = TREND[snapshot?.trend] || TREND.stable;
  const sev = snapshot?.findings_by_severity || {};

  return (
    <div className="flex flex-col gap-6 w-full pb-10">

      {/* ── Header ────────────────────────────────────────────────────── */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2.5">
            <Activity className="w-5 h-5 text-emerald-400" />
            Métricas de Risco &amp; Governança
          </h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Postura · Conformidade · Radar Regulatório · Simulação de Investimento
          </p>
        </div>
        <button
          onClick={load}
          disabled={loading}
          className="p-2.5 rounded-lg border border-white/10 text-gray-500 hover:text-white hover:bg-white/5 hover:border-white/20 transition-all disabled:opacity-40 shrink-0"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {error && <ErrorBanner message={error} />}
      {loading && !snapshot && <Spinner label="Calculando postura de risco..." />}

      {snapshot && (
        <>
          {/* ── Cockpit ─────────────────────────────────────────────── */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">

            {/* Score */}
            <div className={`rounded-2xl border ${c.border} bg-gradient-to-b from-[#0d1421]/90 to-[#060b13]/70 p-6 flex flex-col justify-between relative overflow-hidden`}>
              <div className={`absolute top-0 right-0 w-32 h-32 ${c.bg} rounded-full blur-3xl -mr-10 -mt-10`} />
              <div className="relative z-10">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center gap-2 text-gray-500">
                    <ShieldAlert className="w-4 h-4" />
                    <span className="text-[10px] uppercase tracking-wider font-bold">Risco Atual</span>
                  </div>
                  <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-[10px] font-bold ${c.bg} ${c.text} ${c.border}`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${c.dot}`} />
                    {snapshot.risk_level}
                  </span>
                </div>

                <div className="flex items-end gap-3">
                  <span className={`text-5xl font-black ${c.text} ${c.glow} leading-none`}>{score}</span>
                  <span className="text-sm font-bold text-gray-600 mb-1">/ 100</span>
                </div>
                <p className="text-[10px] text-gray-600 mt-1 font-medium">
                  quanto menor, melhor
                </p>

                <div className="mt-3">
                  <Bar pct={score} className={c.bar} height="h-1.5" />
                </div>

                <div className="flex items-center gap-2 mt-3">
                  <trend.icon className={`w-3.5 h-3.5 ${trend.text}`} />
                  <span className={`text-[11px] font-bold ${trend.text}`}>{trend.label}</span>
                  {snapshot.trend_basis === 'comparable_snapshot' && snapshot.trend_delta !== 0 ? (
                    <span className="text-[10px] text-gray-600">
                      ({snapshot.trend_delta > 0 ? '+' : ''}{snapshot.trend_delta} em 7 dias)
                    </span>
                  ) : (
                    <span className="text-[10px] text-gray-600">
                      (sem base comparável ainda)
                    </span>
                  )}
                </div>

                {snapshot.floor_applied && (
                  <p className="text-[10px] text-amber-400/70 mt-2 leading-relaxed">
                    {snapshot.floor_reason}
                  </p>
                )}
              </div>
            </div>

            {/* Findings */}
            <div className="rounded-2xl border border-white/[0.06] bg-gradient-to-b from-[#0d1421]/80 to-[#060b13]/60 p-6 flex flex-col">
              <div className="flex items-center gap-2 text-gray-500 mb-4">
                <Layers className="w-4 h-4" />
                <span className="text-[10px] uppercase tracking-wider font-bold">Findings Abertos</span>
              </div>
              <div className="flex items-end gap-3">
                <span className="text-4xl font-black text-white leading-none">{snapshot.open_findings}</span>
                <span className="text-xs text-gray-600 mb-1">únicos</span>
              </div>

              <div className="flex items-center gap-3 mt-3 flex-wrap">
                {[
                  ['CRITICAL', 'text-rose-400', sev.CRITICAL],
                  ['HIGH', 'text-red-400', sev.HIGH],
                  ['MEDIUM', 'text-amber-400', sev.MEDIUM],
                  ['LOW', 'text-blue-400', sev.LOW],
                ].filter(([, , v]) => v > 0).map(([k, cls, v]) => (
                  <span key={k} className={`text-[11px] font-bold ${cls}`}>
                    {v} {k.slice(0, 4).toLowerCase()}
                  </span>
                ))}
              </div>

              {snapshot.deduplication?.collapsed > 0 && (
                <p className="text-[10px] text-gray-600 mt-3 leading-relaxed">
                  {snapshot.deduplication.collapsed} duplicata
                  {snapshot.deduplication.collapsed !== 1 ? 's' : ''} de rescan colapsada
                  {snapshot.deduplication.collapsed !== 1 ? 's' : ''}
                  {' '}({snapshot.deduplication.raw} registros brutos)
                </p>
              )}

              <div className="mt-auto pt-3 flex items-center gap-1.5 flex-wrap">
                <span className="text-[10px] text-gray-600 uppercase tracking-wider font-bold">Evidência:</span>
                {(snapshot.tools_present || []).map(t => (
                  <span key={t} className="text-[10px] font-mono text-emerald-300 bg-emerald-500/10 border border-emerald-500/20 px-1.5 py-0.5 rounded">
                    {t}
                  </span>
                ))}
              </div>
            </div>

            {/* KEV */}
            <div className={`rounded-2xl border ${snapshot.kev?.match_count > 0 ? 'border-rose-500/25' : 'border-white/[0.06]'} bg-gradient-to-b from-[#0d1421]/80 to-[#060b13]/60 p-6 flex flex-col`}>
              <div className="flex items-center gap-2 text-gray-500 mb-4">
                <AlertTriangle className="w-4 h-4" />
                <span className="text-[10px] uppercase tracking-wider font-bold">Exploração Ativa (KEV)</span>
              </div>

              {!snapshot.kev?.available ? (
                <>
                  <p className="text-sm text-gray-500">Enriquecimento indisponível</p>
                  <p className="text-[10px] text-gray-600 mt-2 leading-relaxed">
                    O catálogo KEV da CISA não pôde ser consultado. O score foi calculado
                    sem esse fator — nenhum número foi alterado em silêncio.
                  </p>
                </>
              ) : snapshot.kev.match_count > 0 ? (
                <>
                  <div className="flex items-end gap-3">
                    <span className="text-4xl font-black text-rose-400 drop-shadow-[0_0_10px_rgba(244,63,94,0.4)] leading-none">
                      {snapshot.kev.match_count}
                    </span>
                    <span className="text-xs text-gray-500 mb-1">CVEs sob ataque</span>
                  </div>
                  <div className="flex flex-wrap gap-1 mt-3">
                    {snapshot.kev.matches.slice(0, 4).map(cve => (
                      <span key={cve} className="text-[10px] font-mono text-rose-300 bg-rose-500/10 border border-rose-500/25 px-1.5 py-0.5 rounded">
                        {cve}
                      </span>
                    ))}
                  </div>
                  <p className="text-[10px] text-gray-600 mt-auto pt-3 leading-relaxed">
                    Exploração confirmada em campo pela CISA. Estes findings recebem
                    peso maior no cálculo.
                  </p>
                </>
              ) : (
                <>
                  <div className="flex items-center gap-2">
                    <CheckCircle className="w-5 h-5 text-emerald-400" />
                    <span className="text-sm font-bold text-emerald-400">Nenhuma correspondência</span>
                  </div>
                  <p className="text-[10px] text-gray-600 mt-2 leading-relaxed">
                    Nenhuma das suas CVEs consta no catálogo de exploração ativa
                    ({snapshot.kev.count?.toLocaleString('pt-BR')} CVEs monitoradas).
                  </p>
                </>
              )}
            </div>
          </div>

          {/* ── Evolução ────────────────────────────────────────────── */}
          <Panel
            title="Evolução do risco"
            icon={<TrendingUp className="w-4 h-4 text-emerald-400" />}
            right={
              <span className="text-[10px] text-gray-600 font-mono">
                {history.length} dia{history.length !== 1 ? 's' : ''} · 1 ponto/dia
              </span>
            }
          >
            <div className="p-5 h-[260px] w-full">
              {history.length < 2 ? (
                <div className="h-full flex flex-col items-center justify-center gap-2">
                  <p className="text-sm text-gray-500">Histórico insuficiente</p>
                  <p className="text-[11px] text-gray-600 text-center max-w-sm leading-relaxed">
                    A série é construída a partir de snapshots reais gravados no servidor,
                    um por dia. Ela ganha forma conforme a plataforma é usada.
                  </p>
                  {historyNote && (
                    <p className="text-[10px] text-amber-400/70 text-center max-w-md leading-relaxed mt-1">
                      {historyNote}
                    </p>
                  )}
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={history} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                    <defs>
                      <linearGradient id={GRADIENT_ID} x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#f43f5e" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                    <XAxis dataKey="date" tick={{ fill: 'rgba(255,255,255,0.4)', fontSize: 10 }}
                           tickLine={false} axisLine={false} dy={10} />
                    <YAxis domain={[0, 100]} tick={{ fill: 'rgba(255,255,255,0.4)', fontSize: 10 }}
                           tickLine={false} axisLine={false} />
                    <Tooltip content={<HistoryTooltip />} />
                    <Area type="monotone" dataKey="score" stroke="#f43f5e" strokeWidth={2.5}
                          fillOpacity={1} fill={`url(#${GRADIENT_ID})`}
                          activeDot={{ r: 5, fill: '#060b13', stroke: '#f43f5e', strokeWidth: 2.5 }} />
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </div>
          </Panel>

          {/* ── Abas ────────────────────────────────────────────────── */}
          <div className="flex items-center gap-1 bg-white/[0.03] border border-white/[0.06] rounded-xl p-1 w-fit">
            {TABS.map(t => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold transition-all ${
                  tab === t.id
                    ? 'bg-white/10 text-white border border-white/15'
                    : 'text-gray-500 hover:text-gray-300 border border-transparent'
                }`}
              >
                <t.icon className="w-3.5 h-3.5" />
                {t.label}
              </button>
            ))}
          </div>

          {tab === 'compliance' && (
            <ComplianceTab data={compliance} loading={loading} error={null} onToast={showToast} />
          )}
          {tab === 'simulator' && (
            <SimulatorTab currency={currency} onCurrencyChange={setCurrency} onToast={showToast} />
          )}
          {tab === 'radar' && <RadarTab onToast={showToast} />}
          {tab === 'plan' && <ActionPlanTab currency={currency} onToast={showToast} />}
        </>
      )}

      {/* ── Toast ──────────────────────────────────────────────────── */}
      {toast && (
        <div className={`fixed top-6 right-6 z-[500] flex items-center gap-2 px-4 py-3 rounded-lg shadow-2xl border backdrop-blur-md text-xs font-medium animate-in slide-in-from-top-2 ${
          toast.type === 'error'
            ? 'bg-red-950/90 border-red-500/40 text-red-200'
            : 'bg-emerald-950/90 border-emerald-500/40 text-emerald-200'
        }`}>
          {toast.type === 'error'
            ? <XCircle className="w-4 h-4 shrink-0" />
            : <CheckCircle className="w-4 h-4 shrink-0" />}
          {toast.msg}
        </div>
      )}
    </div>
  );
}
