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
 * Aba Plano de Ação — lista de ações + anotações de risco.
 *
 * O campo `verification` vem do servidor, derivado contra o findings.json vivo:
 * marcar "concluído" numa ação cujos findings continuam abertos devolve
 * "não verificado". Não dá para fingir progresso.
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  ClipboardList, Plus, Trash2, Check, Clock, AlertTriangle,
  StickyNote, X, CircleDot, ShieldQuestion,
} from 'lucide-react';
import { Panel, Spinner, ErrorBanner, EmptyState, money, jget, API } from '../ui';

const PRIORITY = {
  P0: { text: 'text-rose-400',  bg: 'bg-rose-500/10',  border: 'border-rose-500/25',  label: 'P0' },
  P1: { text: 'text-red-400',   bg: 'bg-red-500/10',   border: 'border-red-500/25',   label: 'P1' },
  P2: { text: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/25', label: 'P2' },
  P3: { text: 'text-blue-400',  bg: 'bg-blue-500/10',  border: 'border-blue-500/25',  label: 'P3' },
};

const STATUS = {
  todo:        { label: 'A fazer',     text: 'text-gray-400',    bg: 'bg-white/[0.05]' },
  in_progress: { label: 'Em curso',    text: 'text-blue-400',    bg: 'bg-blue-500/10' },
  blocked:     { label: 'Bloqueado',   text: 'text-rose-400',    bg: 'bg-rose-500/10' },
  done:        { label: 'Concluído',   text: 'text-emerald-400', bg: 'bg-emerald-500/10' },
  cancelled:   { label: 'Cancelado',   text: 'text-gray-600',    bg: 'bg-white/[0.03]' },
};

const VERIFICATION = {
  verified:   { label: 'verificado',     text: 'text-emerald-400', icon: Check },
  partial:    { label: 'parcial',        text: 'text-amber-400',   icon: CircleDot },
  unverified: { label: 'não verificado', text: 'text-rose-400',    icon: ShieldQuestion },
  pending:    null,
};

function ActionRow({ action, currency, onPatch, onDelete }) {
  const p = PRIORITY[action.priority] || PRIORITY.P3;
  const s = STATUS[action.status] || STATUS.todo;
  const v = VERIFICATION[action.verification];

  return (
    <div className="px-4 py-3 border-b border-white/[0.04] last:border-0 hover:bg-white/[0.02] transition-colors">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${p.bg} ${p.text} ${p.border}`}>
              {p.label}
            </span>
            <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${s.bg} ${s.text}`}>
              {s.label}
            </span>
            {v && (
              <span className={`text-[9px] font-bold flex items-center gap-1 ${v.text}`}>
                <v.icon className="w-2.5 h-2.5" /> {v.label}
              </span>
            )}
            {action.is_overdue && (
              <span className="text-[9px] font-bold text-rose-400 flex items-center gap-1">
                <AlertTriangle className="w-2.5 h-2.5" /> atrasado
              </span>
            )}
          </div>

          <p className="text-xs font-medium text-gray-200 leading-snug">{action.title}</p>

          <div className="flex items-center gap-3 mt-1.5 flex-wrap">
            {action.findings_total > 0 && (
              <span className="text-[10px] text-gray-600">
                {action.findings_still_open}/{action.findings_total} findings abertos
              </span>
            )}
            {action.estimated_cost && (
              <span className="text-[10px] text-gray-600 font-mono">
                {money(action.estimated_cost, currency)}
              </span>
            )}
            {action.estimated_hours && (
              <span className="text-[10px] text-gray-600">{action.estimated_hours}h</span>
            )}
            {action.control_refs?.length > 0 && (
              <span className="text-[10px] text-gray-600">
                {action.control_refs.length} controle{action.control_refs.length !== 1 ? 's' : ''}
              </span>
            )}
          </div>

          {action.verification === 'unverified' && (
            <p className="text-[10px] text-rose-400/80 mt-1.5 leading-relaxed">
              Marcado como concluído, mas todos os findings continuam abertos no scanner.
              Rode uma nova varredura para confirmar a correção.
            </p>
          )}
        </div>

        <div className="flex items-center gap-1 shrink-0">
          <select
            value={action.status}
            onChange={e => onPatch(action.id, { status: e.target.value })}
            className="bg-[#111827] border border-white/[0.08] rounded-lg px-2 py-1 text-[10px] text-gray-300 focus:outline-none focus:border-emerald-500/40"
          >
            {Object.entries(STATUS).map(([k, val]) => (
              <option key={k} value={k}>{val.label}</option>
            ))}
          </select>
          <button
            onClick={() => onDelete(action.id)}
            className="p-1.5 rounded-lg text-gray-600 hover:text-rose-400 hover:bg-rose-500/10 transition-all"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
}

export default function ActionPlanTab({ currency, onToast }) {
  const [actions, setActions] = useState([]);
  const [notes, setNotes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showForm, setShowForm] = useState(null); // 'action' | 'note'
  const [form, setForm] = useState({ title: '', body: '', kind: 'note' });

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [a, n] = await Promise.all([
        jget('/posture/actions'),
        jget('/posture/annotations'),
      ]);
      setActions(a.actions || []);
      setNotes(n.annotations || []);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const patchAction = async (id, patch) => {
    try {
      const res = await fetch(`${API}/posture/actions/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(patch),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      load();
    } catch (e) { onToast?.('error', e.message); }
  };

  const removeAction = async (id) => {
    try {
      await fetch(`${API}/posture/actions/${id}`, { method: 'DELETE' });
      onToast?.('success', 'Item removido');
      load();
    } catch (e) { onToast?.('error', e.message); }
  };

  const removeNote = async (id) => {
    try {
      await fetch(`${API}/posture/annotations/${id}`, { method: 'DELETE' });
      onToast?.('success', 'Anotação removida');
      load();
    } catch (e) { onToast?.('error', e.message); }
  };

  const submit = async (e) => {
    e.preventDefault();
    if (!form.title.trim()) return;
    const isNote = showForm === 'note';
    try {
      const res = await fetch(`${API}/posture/${isNote ? 'annotations' : 'actions'}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(
          isNote
            ? { title: form.title, body: form.body, kind: form.kind, scope: 'global' }
            : { title: form.title, description: form.body, source: 'manual' }
        ),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setForm({ title: '', body: '', kind: 'note' });
      setShowForm(null);
      onToast?.('success', isNote ? 'Anotação criada' : 'Item adicionado ao plano');
      load();
    } catch (e) { onToast?.('error', e.message); }
  };

  if (loading && !actions.length && !notes.length) return <Spinner label="Carregando plano..." />;
  if (error) return <ErrorBanner message={error} />;

  const open = actions.filter(a => !['done', 'cancelled'].includes(a.status));
  const totalCost = open.reduce((s, a) => s + (a.estimated_cost?.[currency.toLowerCase()] || 0), 0);

  return (
    <div className="flex flex-col gap-5">
      {/* Resumo */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: 'Abertos', value: open.length, cls: 'text-white', border: 'border-white/[0.08]' },
          { label: 'P0 / P1', value: actions.filter(a => ['P0', 'P1'].includes(a.priority) && !['done','cancelled'].includes(a.status)).length, cls: 'text-rose-400', border: 'border-rose-500/15' },
          { label: 'Atrasados', value: actions.filter(a => a.is_overdue).length, cls: 'text-amber-400', border: 'border-amber-500/15' },
          { label: 'Não verificados', value: actions.filter(a => a.verification === 'unverified').length, cls: 'text-orange-400', border: 'border-orange-500/15' },
        ].map(k => (
          <div key={k.label} className={`flex items-center justify-between px-4 py-3.5 rounded-xl bg-gradient-to-b from-[#0d1421]/70 to-[#060b13]/60 border ${k.border}`}>
            <p className="text-[10px] text-gray-600 uppercase tracking-wider font-bold">{k.label}</p>
            <span className={`text-2xl font-black ${k.cls}`}>{k.value}</span>
          </div>
        ))}
      </div>

      {/* Ações */}
      <Panel
        title={`Plano de ação${totalCost > 0 ? ` — ${currency === 'BRL' ? 'R$' : '$'} ${totalCost.toLocaleString('pt-BR', { maximumFractionDigits: 0 })} em aberto` : ''}`}
        icon={<ClipboardList className="w-4 h-4 text-emerald-400" />}
        accent="from-emerald-500/50 to-teal-500/25"
        right={
          <button
            onClick={() => setShowForm(showForm === 'action' ? null : 'action')}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-white/[0.08] bg-white/[0.03] text-[11px] font-bold text-gray-400 hover:text-white hover:bg-white/[0.06] transition-all"
          >
            {showForm === 'action' ? <><X className="w-3 h-3" /> Cancelar</> : <><Plus className="w-3 h-3" /> Novo item</>}
          </button>
        }
      >
        {showForm === 'action' && (
          <form onSubmit={submit} className="p-4 border-b border-white/[0.05] bg-[#030710]/50 flex flex-col gap-2.5">
            <input
              autoFocus
              value={form.title}
              onChange={e => setForm(f => ({ ...f, title: e.target.value }))}
              placeholder="O que precisa ser feito?"
              className="w-full bg-[#111827] border border-white/[0.08] rounded-xl px-3.5 py-2 text-sm text-white placeholder:text-gray-600 focus:outline-none focus:border-emerald-500/40"
            />
            <textarea
              value={form.body}
              onChange={e => setForm(f => ({ ...f, body: e.target.value }))}
              placeholder="Detalhes (opcional)"
              rows={2}
              className="w-full bg-[#111827] border border-white/[0.08] rounded-xl px-3.5 py-2 text-xs text-white placeholder:text-gray-600 focus:outline-none focus:border-emerald-500/40 resize-none"
            />
            <button type="submit" className="self-start px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold transition-colors">
              Adicionar
            </button>
          </form>
        )}

        {actions.length === 0 ? (
          <EmptyState
            icon={<ClipboardList className="w-5 h-5 text-gray-600" />}
            title="Plano vazio"
            subtitle="Adicione itens manualmente ou envie pacotes direto do Simulador e das lacunas de cobertura em Conformidade."
          />
        ) : (
          <div className="max-h-[520px] overflow-y-auto">
            {actions.map(a => (
              <ActionRow key={a.id} action={a} currency={currency}
                         onPatch={patchAction} onDelete={removeAction} />
            ))}
          </div>
        )}
      </Panel>

      {/* Anotações */}
      <Panel
        title="Anotações de risco"
        icon={<StickyNote className="w-4 h-4 text-amber-400" />}
        accent="from-amber-500/50 to-orange-500/25"
        right={
          <button
            onClick={() => setShowForm(showForm === 'note' ? null : 'note')}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-white/[0.08] bg-white/[0.03] text-[11px] font-bold text-gray-400 hover:text-white hover:bg-white/[0.06] transition-all"
          >
            {showForm === 'note' ? <><X className="w-3 h-3" /> Cancelar</> : <><Plus className="w-3 h-3" /> Nova anotação</>}
          </button>
        }
      >
        {showForm === 'note' && (
          <form onSubmit={submit} className="p-4 border-b border-white/[0.05] bg-[#030710]/50 flex flex-col gap-2.5">
            <div className="flex gap-2.5">
              <input
                autoFocus
                value={form.title}
                onChange={e => setForm(f => ({ ...f, title: e.target.value }))}
                placeholder="Título da anotação"
                className="flex-1 bg-[#111827] border border-white/[0.08] rounded-xl px-3.5 py-2 text-sm text-white placeholder:text-gray-600 focus:outline-none focus:border-amber-500/40"
              />
              <select
                value={form.kind}
                onChange={e => setForm(f => ({ ...f, kind: e.target.value }))}
                className="bg-[#111827] border border-white/[0.08] rounded-xl px-3 py-2 text-xs text-gray-300 focus:outline-none focus:border-amber-500/40"
              >
                <option value="note">Nota</option>
                <option value="risk_acceptance">Aceite de risco</option>
                <option value="compensating_control">Controle compensatório</option>
                <option value="evidence">Evidência</option>
              </select>
            </div>
            <textarea
              value={form.body}
              onChange={e => setForm(f => ({ ...f, body: e.target.value }))}
              placeholder="Contexto, justificativa, decisão tomada..."
              rows={3}
              className="w-full bg-[#111827] border border-white/[0.08] rounded-xl px-3.5 py-2 text-xs text-white placeholder:text-gray-600 focus:outline-none focus:border-amber-500/40 resize-none"
            />
            <button type="submit" className="self-start px-4 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold transition-colors">
              Salvar anotação
            </button>
          </form>
        )}

        {notes.length === 0 ? (
          <EmptyState
            icon={<StickyNote className="w-5 h-5 text-gray-600" />}
            title="Nenhuma anotação"
            subtitle="Registre decisões, aceites de risco e controles compensatórios. Cada anotação guarda a postura de risco do momento em que foi escrita."
          />
        ) : (
          <div className="max-h-[420px] overflow-y-auto">
            {notes.map(n => (
              <div key={n.id} className="px-4 py-3 border-b border-white/[0.04] last:border-0 hover:bg-white/[0.02] transition-colors">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <span className="text-[9px] font-bold px-1.5 py-0.5 rounded border text-amber-300 bg-amber-500/10 border-amber-500/25">
                        {n.kind === 'risk_acceptance' ? 'aceite de risco'
                          : n.kind === 'compensating_control' ? 'controle compensatório'
                          : n.kind === 'evidence' ? 'evidência' : 'nota'}
                      </span>
                      {n.is_expired && (
                        <span className="text-[9px] font-bold text-rose-400">expirado</span>
                      )}
                      {n.risk_snapshot && (
                        <span className="text-[10px] text-gray-600">
                          risco na época: {n.risk_snapshot.risk_score}
                        </span>
                      )}
                    </div>
                    <p className="text-xs font-medium text-gray-200">{n.title}</p>
                    {n.body && (
                      <p className="text-[11px] text-gray-500 mt-1 leading-relaxed whitespace-pre-wrap">{n.body}</p>
                    )}
                    <p className="text-[10px] text-gray-700 mt-1.5 flex items-center gap-1">
                      <Clock className="w-2.5 h-2.5" />
                      {new Date(n.created_at).toLocaleString('pt-BR')}
                    </p>
                  </div>
                  <button
                    onClick={() => removeNote(n.id)}
                    className="p-1.5 rounded-lg text-gray-600 hover:text-rose-400 hover:bg-rose-500/10 transition-all shrink-0"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
