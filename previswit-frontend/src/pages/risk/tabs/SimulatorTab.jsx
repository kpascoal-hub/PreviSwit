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
 * Aba Simulador — "coloca R$ 20.000 e vê o que melhorar".
 *
 * O toggle BRL/USD é display puro: a API devolve todo valor monetário nas duas
 * moedas, então não há aritmética no cliente e as duas visões nunca divergem.
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  Calculator, TrendingDown, Plus, Check, ChevronRight, Zap,
  ArrowRight, Ban, Sparkles, Loader2,
} from 'lucide-react';
import {
  Panel, Bar, money, riskColors, complianceColors, SevBadge,
  ScopeNote, Spinner, ErrorBanner, EmptyState, API,
} from '../ui';

const PRESETS = [5000, 10000, 20000, 50000];

function ScoreDelta({ before, after }) {
  const cb = riskColors(before);
  const ca = riskColors(after);
  return (
    <div className="flex items-center gap-4">
      <div className="text-center">
        <p className="text-[9px] text-gray-600 uppercase tracking-wider font-bold mb-1">Agora</p>
        <span className={`text-3xl font-black ${cb.text}`}>{before}</span>
      </div>
      <ArrowRight className="w-5 h-5 text-gray-600 mt-3" />
      <div className="text-center">
        <p className="text-[9px] text-gray-600 uppercase tracking-wider font-bold mb-1">Depois</p>
        <span className={`text-3xl font-black ${ca.text} ${ca.glow}`}>{after}</span>
      </div>
    </div>
  );
}

function PackageRow({ pkg, index, currency, onAdd, addedIds }) {
  const [open, setOpen] = useState(false);
  const added = addedIds[pkg.id];

  return (
    <div className="border-b border-white/[0.04] last:border-0">
      <div
        onClick={() => setOpen(o => !o)}
        className={`grid grid-cols-12 gap-3 items-center px-4 py-3 cursor-pointer hover:bg-white/[0.025] transition-colors ${index % 2 ? 'bg-white/[0.01]' : ''}`}
      >
        <div className="col-span-1 text-[11px] font-mono text-gray-600">
          #{String(pkg.rank || index + 1).padStart(2, '0')}
        </div>
        <div className="col-span-5 min-w-0">
          <p className="text-xs font-medium text-gray-200 truncate">{pkg.title}</p>
          <p className="text-[10px] text-gray-600 mt-0.5">
            {pkg.family_label} · {pkg.hours}h
          </p>
        </div>
        <div className="col-span-2">
          <SevBadge sev={pkg.worst_severity} />
        </div>
        <div className="col-span-2 text-xs font-mono text-gray-300">
          {money(pkg.cost, currency)}
        </div>
        <div className="col-span-2 flex items-center justify-end gap-2">
          <span className="text-[10px] font-bold text-emerald-400">
            {pkg.efficiency_per_1k}/1k
          </span>
          <ChevronRight className={`w-3.5 h-3.5 text-gray-600 transition-transform ${open ? 'rotate-90' : ''}`} />
        </div>
      </div>

      {open && (
        <div className="px-4 py-3 bg-[#030710]/70 border-b border-white/[0.04]">
          <div className="grid grid-cols-3 gap-4 text-xs mb-3">
            <div>
              <p className="text-[10px] text-gray-500 uppercase tracking-wider font-bold mb-1">Resolve</p>
              <p className="text-gray-300">{pkg.findings_count} findings</p>
            </div>
            <div>
              <p className="text-[10px] text-gray-500 uppercase tracking-wider font-bold mb-1">Pontos de risco</p>
              <p className="text-gray-300">{pkg.risk_points}</p>
            </div>
            <div>
              <p className="text-[10px] text-gray-500 uppercase tracking-wider font-bold mb-1">Contribuição</p>
              <p className="text-gray-300">{pkg.score_contribution_pct ?? '—'}%</p>
            </div>
          </div>

          <p className="text-[10px] text-gray-500 uppercase tracking-wider font-bold mb-1.5">
            Como o custo foi estimado
          </p>
          <ul className="flex flex-col gap-1 mb-3">
            {pkg.estimate.assumptions.map((a, i) => (
              <li key={i} className="text-[11px] text-gray-500 leading-relaxed flex gap-1.5">
                <span className="text-gray-700">·</span>{a}
              </li>
            ))}
          </ul>

          <button
            onClick={(e) => { e.stopPropagation(); onAdd(pkg); }}
            disabled={added}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-emerald-500/25 bg-emerald-500/10 text-[11px] font-bold text-emerald-300 hover:bg-emerald-500/20 transition-colors disabled:opacity-50"
          >
            {added ? <><Check className="w-3 h-3" /> No plano</> : <><Plus className="w-3 h-3" /> Adicionar ao plano</>}
          </button>
        </div>
      )}
    </div>
  );
}

export default function SimulatorTab({ currency, onCurrencyChange, onToast }) {
  const [budget, setBudget] = useState(20000);
  const [input, setInput] = useState('20000');
  const [sim, setSim] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [addedIds, setAddedIds] = useState({});
  const [ai, setAi] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);

  const run = useCallback(async (amount, curr) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API}/posture/simulate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ budget: amount, currency: curr }),
      });
      if (!res.ok) {
        const j = await res.json().catch(() => ({}));
        throw new Error(j.detail?.detail || j.detail || `HTTP ${res.status}`);
      }
      setSim(await res.json());
    } catch (e) {
      setError(e.message);
      setSim(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { run(budget, currency); }, [budget, currency, run]);

  const addPackage = async (pkg) => {
    try {
      const res = await fetch(`${API}/posture/actions/from-package/${encodeURIComponent(pkg.id)}`, {
        method: 'POST',
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setAddedIds(a => ({ ...a, [pkg.id]: true }));
      onToast?.('success', `"${pkg.title}" adicionado ao plano`);
    } catch (e) {
      onToast?.('error', `Falha: ${e.message}`);
    }
  };

  const askAi = async () => {
    setAiLoading(true);
    setAi(null);
    try {
      const key = sessionStorage.getItem('gemini_api_key') || sessionStorage.getItem('GEMINI_KEY') || sessionStorage.getItem('gemini_key');
      const res = await fetch(`${API}/posture/ai-insight`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(key ? { 'X-Gemini-Key': key } : {}),
        },
        body: JSON.stringify({ focus: 'business', budget, currency }),
      });
      setAi(await res.json());
    } catch (e) {
      onToast?.('error', `Falha na IA: ${e.message}`);
    } finally {
      setAiLoading(false);
    }
  };

  const submit = (e) => {
    e.preventDefault();
    const v = parseFloat(String(input).replace(/[^\d.,]/g, '').replace(',', '.'));
    if (v > 0) setBudget(v);
  };

  return (
    <div className="flex flex-col gap-5">
      {/* Controles */}
      <Panel
        title="Simulador de investimento"
        icon={<Calculator className="w-4 h-4 text-violet-400" />}
        accent="from-violet-500/50 to-fuchsia-500/25"
        right={
          <div className="flex items-center bg-white/[0.03] border border-white/[0.06] rounded-lg p-0.5 gap-0.5">
            {['BRL', 'USD'].map(c => (
              <button
                key={c}
                onClick={() => onCurrencyChange(c)}
                className={`px-2.5 py-1 rounded-md text-[10px] font-bold transition-all ${
                  currency === c ? 'bg-white/10 text-white' : 'text-gray-600 hover:text-gray-300'
                }`}
              >
                {c === 'BRL' ? 'R$' : 'US$'}
              </button>
            ))}
          </div>
        }
      >
        <div className="p-5">
          <form onSubmit={submit} className="flex gap-3">
            <div className="flex-1 relative">
              <span className="absolute left-3.5 top-1/2 -translate-y-1/2 text-sm text-gray-500 font-bold">
                {currency === 'BRL' ? 'R$' : '$'}
              </span>
              <input
                type="text"
                value={input}
                onChange={e => setInput(e.target.value)}
                className="w-full bg-[#111827] border border-white/[0.08] rounded-xl pl-11 pr-4 py-2.5 text-sm text-white placeholder:text-gray-600 focus:outline-none focus:border-violet-500/40 focus:ring-1 focus:ring-violet-500/20 transition-all"
                placeholder="20000"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold bg-violet-600 hover:bg-violet-500 text-white shadow-lg shadow-violet-500/20 transition-all disabled:opacity-50"
            >
              {loading
                ? <><Loader2 className="w-4 h-4 animate-spin" /> Otimizando...</>
                : <><Calculator className="w-4 h-4" /> Simular</>}
            </button>
          </form>

          <div className="flex items-center gap-2 mt-3">
            <span className="text-[10px] text-gray-600 uppercase tracking-wider font-bold">Rápido:</span>
            {PRESETS.map(p => (
              <button
                key={p}
                onClick={() => { setInput(String(p)); setBudget(p); }}
                className={`px-2.5 py-1 rounded-lg text-[11px] font-bold border transition-all ${
                  budget === p
                    ? 'bg-violet-500/15 text-violet-300 border-violet-500/30'
                    : 'bg-white/[0.03] text-gray-500 border-white/[0.06] hover:text-gray-300'
                }`}
              >
                {currency === 'BRL' ? 'R$ ' : '$ '}{p.toLocaleString('pt-BR')}
              </button>
            ))}
          </div>
        </div>
      </Panel>

      {error && <ErrorBanner message={error} />}
      {loading && !sim && <Spinner label="Resolvendo otimização..." />}

      {sim && !loading && (
        <>
          {/* Antes / Depois */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            <Panel title="Impacto no risco" icon={<TrendingDown className="w-4 h-4 text-emerald-400" />}>
              <div className="p-5 flex flex-col items-center gap-3">
                <ScoreDelta before={sim.before.risk_score} after={sim.after.risk_score} />
                <p className="text-xs text-emerald-400 font-bold">
                  {sim.delta.risk_score} pontos
                </p>
                <p className="text-[10px] text-gray-600 text-center">
                  {sim.delta.findings_resolved} findings resolvidos ·
                  {' '}{sim.before.open_findings} → {sim.after.open_findings} abertos
                </p>
              </div>
            </Panel>

            <Panel title="Conformidade" icon={<Zap className="w-4 h-4 text-lime-400" />}>
              <div className="p-5">
                <div className="flex items-end gap-2 mb-2">
                  <span className="text-2xl font-black text-gray-500">
                    {sim.before.compliance.overall}%
                  </span>
                  <ArrowRight className="w-4 h-4 text-gray-600 mb-1.5" />
                  <span className={`text-3xl font-black ${complianceColors(sim.after.compliance.overall).text}`}>
                    {sim.after.compliance.overall}%
                  </span>
                </div>
                <Bar pct={sim.after.compliance.overall} className={complianceColors(sim.after.compliance.overall).bar} />
                <p className="text-[10px] text-gray-600 mt-2">
                  +{sim.delta.compliance_overall} pontos percentuais no agregado
                </p>
              </div>
            </Panel>

            <Panel title="Orçamento" icon={<Calculator className="w-4 h-4 text-violet-400" />}>
              <div className="p-5 flex flex-col gap-2.5">
                <div className="flex justify-between text-xs">
                  <span className="text-gray-500">Disponível</span>
                  <span className="text-gray-300 font-mono">{money(sim.budget, currency)}</span>
                </div>
                <div className="flex justify-between text-xs">
                  <span className="text-gray-500">Alocado</span>
                  <span className="text-violet-300 font-mono font-bold">{money(sim.spent, currency)}</span>
                </div>
                <div className="flex justify-between text-xs">
                  <span className="text-gray-500">Sobra</span>
                  <span className="text-gray-400 font-mono">{money(sim.leftover, currency)}</span>
                </div>
                <Bar
                  pct={(sim.spent.brl / sim.budget.brl) * 100}
                  className="bg-violet-500"
                  height="h-1.5"
                />
                <p className="text-[10px] text-gray-600 leading-relaxed">{sim.leftover_note}</p>
              </div>
            </Panel>
          </div>

          {/* Prova do otimizador */}
          <div className="rounded-xl border border-white/[0.06] bg-[#0d1421]/50 px-4 py-3">
            <div className="flex items-center justify-between gap-4 flex-wrap">
              <div className="flex items-center gap-2">
                <Sparkles className="w-3.5 h-3.5 text-violet-400" />
                <span className="text-[11px] text-gray-400">
                  Knapsack 0/1 exato · {sim.optimizer.packages_considered} pacotes ·
                  {' '}<span className="text-violet-300 font-bold">{sim.optimizer.dp_risk_points} pts</span>
                </span>
              </div>
              {sim.optimizer.dp_advantage_pct > 0 && (
                <span className="text-[11px] text-emerald-400 font-bold">
                  +{sim.optimizer.dp_advantage_pct}% vs. heurística gulosa
                  ({sim.optimizer.greedy_baseline_risk_points} pts)
                </span>
              )}
            </div>
            <p className="text-[10px] text-gray-600 mt-1.5 leading-relaxed">{sim.optimizer.note}</p>
          </div>

          {/* Selecionados */}
          <Panel
            title={`Plano recomendado — ${sim.selected.length} pacote${sim.selected.length !== 1 ? 's' : ''}`}
            icon={<Check className="w-4 h-4 text-emerald-400" />}
            accent="from-emerald-500/50 to-teal-500/25"
          >
            {sim.selected.length === 0 ? (
              <EmptyState
                icon={<Ban className="w-5 h-5 text-gray-600" />}
                title="Orçamento insuficiente"
                subtitle="Nenhum pacote cabe no valor informado. Aumente o orçamento para ver recomendações."
              />
            ) : (
              <>
                <div className="grid grid-cols-12 gap-3 px-4 py-2 text-[9px] text-gray-500 uppercase tracking-wider font-bold bg-[#030710]/60 border-b border-white/[0.04]">
                  <div className="col-span-1">#</div>
                  <div className="col-span-5">Pacote</div>
                  <div className="col-span-2">Severidade</div>
                  <div className="col-span-2">Custo</div>
                  <div className="col-span-2 text-right">Eficiência</div>
                </div>
                {sim.selected.map((p, i) => (
                  <PackageRow key={p.id} pkg={p} index={i} currency={currency}
                              onAdd={addPackage} addedIds={addedIds} />
                ))}
              </>
            )}
          </Panel>

          {/* IA */}
          <Panel
            title="Análise executiva por IA"
            icon={<Sparkles className="w-4 h-4 text-violet-400" />}
            accent="from-violet-500/50 to-fuchsia-500/25"
            right={
              <button
                onClick={askAi}
                disabled={aiLoading}
                className="flex items-center gap-1.5 px-3 py-1 rounded-lg border border-violet-500/25 bg-violet-500/10 text-[11px] font-bold text-violet-300 hover:bg-violet-500/20 transition-colors disabled:opacity-50"
              >
                {aiLoading ? <><Loader2 className="w-3 h-3 animate-spin" /> Gerando...</> : <>Gerar análise</>}
              </button>
            }
          >
            <div className="p-5">
              {!ai && !aiLoading && (
                <p className="text-xs text-gray-600 leading-relaxed">
                  Gera uma leitura executiva desta simulação. Todos os números entregues ao
                  modelo vêm do cálculo do servidor — e o bloco de dados exato fica visível
                  abaixo da resposta para conferência.
                </p>
              )}
              {aiLoading && <Spinner label="Consultando Gemini..." />}
              {ai && (
                <>
                  {ai.source === 'deterministic_fallback' && (
                    <div className="mb-3 px-3 py-2 rounded-lg bg-amber-500/[0.07] border border-amber-500/20">
                      <p className="text-[11px] text-amber-400">{ai.unavailable_reason}</p>
                    </div>
                  )}
                  <div className="text-xs text-gray-300 leading-relaxed whitespace-pre-wrap">
                    {ai.response || ai.deterministic_summary}
                  </div>
                  {ai.grounding && (
                    <details className="mt-4 pt-3 border-t border-white/[0.05]">
                      <summary className="text-[10px] text-gray-600 uppercase tracking-wider font-bold cursor-pointer hover:text-gray-400">
                        Dados que fundamentaram a resposta
                      </summary>
                      <pre className="mt-2 text-[10px] text-gray-600 bg-[#030710]/70 rounded-lg p-3 overflow-x-auto max-h-64">
                        {JSON.stringify(ai.grounding, null, 2)}
                      </pre>
                    </details>
                  )}
                </>
              )}
            </div>
          </Panel>

          {/* Excluídos */}
          {sim.excluded?.length > 0 && (
            <Panel title={`Não selecionados — ${sim.excluded.length}`} icon={<Ban className="w-4 h-4 text-gray-500" />} accent="from-white/10 to-white/0">
              <div className="max-h-72 overflow-y-auto">
                {sim.excluded.map(e => (
                  <div key={e.package_id} className="flex items-start justify-between gap-4 px-4 py-2.5 border-b border-white/[0.04] last:border-0">
                    <div className="min-w-0">
                      <p className="text-xs text-gray-400 truncate">{e.title}</p>
                      <p className="text-[10px] text-gray-600 mt-0.5 leading-relaxed">{e.explanation}</p>
                    </div>
                    <span className="text-[11px] font-mono text-gray-500 shrink-0">
                      {money(e.cost, currency)}
                    </span>
                  </div>
                ))}
              </div>
            </Panel>
          )}

          <ScopeNote>{sim.disclaimer}</ScopeNote>
        </>
      )}
    </div>
  );
}
