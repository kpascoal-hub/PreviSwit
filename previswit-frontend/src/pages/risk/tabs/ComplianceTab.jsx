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
 * Aba Conformidade — 7 frameworks com escopo honesto.
 *
 * Regra da tela: NENHUM percentual aparece sem o denominador ao lado.
 * "ISO 27001: 39,2%" sozinho é propaganda; "39,2% sobre 6 dos 93 controles"
 * é informação.
 */

import React, { useState } from 'react';
import {
  ShieldCheck, ChevronRight, ExternalLink, Wrench, Plus, Check,
} from 'lucide-react';
import { Panel, Bar, complianceColors, ScopeNote, Spinner, ErrorBanner, API } from '../ui';

function ControlRow({ control, familyLabels }) {
  const [open, setOpen] = useState(false);
  const health = control.health_pct;
  const c = complianceColors(health ?? 0);

  return (
    <div className="border-b border-white/[0.04] last:border-0">
      <div
        onClick={() => setOpen(o => !o)}
        className="grid grid-cols-12 gap-3 items-center px-4 py-2.5 cursor-pointer hover:bg-white/[0.025] transition-colors"
      >
        <div className="col-span-2 font-mono text-[11px] text-gray-400 truncate">{control.id}</div>
        <div className="col-span-5 min-w-0">
          <p className="text-xs text-gray-300 truncate">{control.title}</p>
        </div>
        <div className="col-span-2">
          {control.in_scope ? (
            <div className="flex items-center gap-2">
              <span className={`text-xs font-bold ${c.text} w-10`}>{health}%</span>
              <div className="flex-1"><Bar pct={health} className={c.bar} height="h-1" /></div>
            </div>
          ) : (
            <span className="text-[10px] text-gray-600 italic">não avaliado</span>
          )}
        </div>
        <div className="col-span-2 text-[10px] text-gray-500">
          {control.in_scope
            ? `${control.open_findings} finding${control.open_findings !== 1 ? 's' : ''}`
            : '—'}
        </div>
        <div className="col-span-1 flex justify-end">
          <ChevronRight className={`w-3.5 h-3.5 text-gray-600 transition-transform ${open ? 'rotate-90' : ''}`} />
        </div>
      </div>

      {open && (
        <div className="px-4 py-3 bg-[#030710]/70 border-b border-white/[0.04] text-xs">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <p className="text-[10px] text-gray-500 uppercase tracking-wider font-bold mb-1">Famílias mapeadas</p>
              <div className="flex flex-wrap gap-1">
                {control.families.map(f => (
                  <span key={f} className="text-[10px] text-gray-400 bg-white/[0.04] border border-white/[0.06] px-2 py-0.5 rounded-md">
                    {familyLabels?.[f] || f}
                  </span>
                ))}
              </div>
            </div>
            <div>
              <p className="text-[10px] text-gray-500 uppercase tracking-wider font-bold mb-1">Importância</p>
              <p className="text-gray-400">{'★'.repeat(control.importance)}{'☆'.repeat(3 - control.importance)}</p>
            </div>
          </div>
          {!control.in_scope && (
            <p className="mt-3 text-[11px] text-amber-400/80 leading-relaxed">
              Nenhuma ferramenta presente cobre este controle. Ele não entra no cálculo —
              pontuá-lo como conforme seria afirmar que algo foi verificado quando não foi.
            </p>
          )}
        </div>
      )}
    </div>
  );
}

function FrameworkCard({ fw, familyLabels, expanded, onToggle, onCreateAction }) {
  const c = complianceColors(fw.compliance_percentage);
  const coveragePct = Math.round(fw.coverage_of_catalog * 1000) / 10;

  return (
    <div className={`rounded-2xl border ${c.border} bg-gradient-to-b from-[#0d1421]/80 to-[#060b13]/60 overflow-hidden`}>
      <div className="p-5">
        <div className="flex items-start justify-between gap-4 mb-4">
          <div className="min-w-0">
            <p className="text-sm font-bold text-white truncate">{fw.name}</p>
            <p className="text-[10px] text-gray-500 mt-0.5">{fw.authority} · {fw.version}</p>
          </div>
          <a href={fw.url} target="_blank" rel="noopener noreferrer"
             className="text-gray-600 hover:text-gray-300 transition-colors shrink-0">
            <ExternalLink className="w-3.5 h-3.5" />
          </a>
        </div>

        <div className="flex items-end gap-2 mb-1">
          <span className={`text-4xl font-black ${c.text} leading-none`}>{fw.compliance_percentage}%</span>
          <span className="text-[11px] text-gray-500 mb-1">de conformidade</span>
        </div>
        <Bar pct={fw.compliance_percentage} className={c.bar} />

        {/* O denominador, sempre visível */}
        <div className="mt-3 grid grid-cols-2 gap-3 text-[10px]">
          <div className="bg-white/[0.03] border border-white/[0.05] rounded-lg px-2.5 py-2">
            <p className="text-gray-600 uppercase tracking-wider font-bold">Em escopo</p>
            <p className="text-gray-300 font-bold mt-0.5">
              {fw.in_scope_controls} de {fw.catalog_total_controls}
            </p>
            <p className="text-gray-600 mt-0.5">{coveragePct}% do catálogo</p>
          </div>
          <div className="bg-white/[0.03] border border-white/[0.05] rounded-lg px-2.5 py-2">
            <p className="text-gray-600 uppercase tracking-wider font-bold">Unidade</p>
            <p className="text-gray-300 font-bold mt-0.5 capitalize">{fw.granularity_label}</p>
            <p className="text-gray-600 mt-0.5">{fw.status_label}</p>
          </div>
        </div>

        {fw.coverage_gaps?.length > 0 && (
          <div className="mt-3 rounded-lg border border-amber-500/20 bg-amber-500/[0.06] p-2.5">
            <p className="text-[10px] text-amber-400 uppercase tracking-wider font-bold flex items-center gap-1.5 mb-1.5">
              <Wrench className="w-3 h-3" />
              Ampliar cobertura
            </p>
            <p className="text-[11px] text-gray-400 leading-relaxed">
              Habilitar{' '}
              <span className="text-amber-300 font-semibold">
                {[...new Set(fw.coverage_gaps.flatMap(g => g.enable_tools))].join(', ')}
              </span>{' '}
              colocaria mais {fw.coverage_gaps.length} {fw.granularity_label}
              {fw.coverage_gaps.length !== 1 ? 's' : ''} em escopo.
            </p>
            <button
              onClick={() => onCreateAction(fw)}
              className="mt-2 flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-amber-500/25 bg-amber-500/10 text-[10px] font-bold text-amber-300 hover:bg-amber-500/20 transition-colors"
            >
              <Plus className="w-3 h-3" /> Adicionar ao plano
            </button>
          </div>
        )}

        <button
          onClick={onToggle}
          className="mt-3 w-full flex items-center justify-center gap-1.5 py-1.5 rounded-lg border border-white/[0.08] bg-white/[0.03] text-[11px] font-bold text-gray-400 hover:text-white hover:bg-white/[0.06] transition-all"
        >
          {expanded ? 'Ocultar controles' : `Ver ${fw.technical_subset_size} controles`}
          <ChevronRight className={`w-3 h-3 transition-transform ${expanded ? 'rotate-90' : ''}`} />
        </button>
      </div>

      {expanded && (
        <div className="border-t border-white/[0.05]">
          <div className="grid grid-cols-12 gap-3 px-4 py-2 text-[9px] text-gray-500 uppercase tracking-wider font-bold bg-[#030710]/60 border-b border-white/[0.04]">
            <div className="col-span-2">ID</div>
            <div className="col-span-5">Controle</div>
            <div className="col-span-2">Saúde</div>
            <div className="col-span-2">Findings</div>
            <div className="col-span-1" />
          </div>
          <div className="max-h-[380px] overflow-y-auto">
            {fw.controls.map(c => (
              <ControlRow key={c.id} control={c} familyLabels={familyLabels} />
            ))}
          </div>
          <div className="px-4 py-3 bg-[#030710]/40 border-t border-white/[0.04]">
            <ScopeNote>{fw.scope_note}</ScopeNote>
          </div>
        </div>
      )}
    </div>
  );
}

export default function ComplianceTab({ data, loading, error, onToast }) {
  const [expanded, setExpanded] = useState(null);
  const [added, setAdded] = useState({});

  const createGapAction = async (fw) => {
    const tools = [...new Set(fw.coverage_gaps.flatMap(g => g.enable_tools))];
    try {
      const res = await fetch(`${API}/posture/actions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: `Habilitar ${tools.join(' + ')} para ampliar cobertura de ${fw.name}`,
          description:
            `Hoje ${fw.in_scope_controls} de ${fw.catalog_total_controls} ${fw.granularity_label}s ` +
            `estão em escopo de avaliação. Habilitar ${tools.join(', ')} colocaria mais ` +
            `${fw.coverage_gaps.length} em escopo: ${fw.coverage_gaps.map(g => g.control).join(', ')}.`,
          source: 'coverage_gap',
          source_ref: fw.key,
          control_refs: fw.coverage_gaps.map(g => `${fw.key}:${g.control}`),
        }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setAdded(a => ({ ...a, [fw.key]: true }));
      onToast?.('success', 'Item adicionado ao plano de ação');
    } catch (e) {
      onToast?.('error', `Falha ao criar item: ${e.message}`);
    }
  };

  if (loading) return <Spinner label="Mapeando findings para controles..." />;
  if (error) return <ErrorBanner message={error} />;
  if (!data) return null;

  const frameworks = Object.values(data.frameworks || {});
  const oc = complianceColors(data.overall_compliance);

  return (
    <div className="flex flex-col gap-5">
      {/* Agregado */}
      <Panel
        title="Conformidade agregada"
        icon={<ShieldCheck className="w-4 h-4 text-emerald-400" />}
        accent="from-emerald-500/50 to-teal-500/25"
      >
        <div className="p-5">
          <div className="flex items-end gap-3 mb-2">
            <span className={`text-5xl font-black ${oc.text} leading-none`}>
              {data.overall_compliance}%
            </span>
            <span className="text-xs text-gray-500 mb-1.5">
              ponderado por controles em escopo
            </span>
          </div>
          <Bar pct={data.overall_compliance} className={oc.bar} height="h-2.5" />

          <div className="mt-4 flex flex-wrap items-center gap-2">
            <span className="text-[10px] text-gray-500 uppercase tracking-wider font-bold">
              Evidência de:
            </span>
            {(data.evidence?.tools_present || []).map(t => (
              <span key={t} className="text-[10px] font-mono text-emerald-300 bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 rounded-md">
                {t}
              </span>
            ))}
            {data.deduplication && (
              <span className="text-[10px] text-gray-600 ml-auto">
                {data.deduplication.canonical} findings únicos
                {data.deduplication.collapsed > 0 && ` (${data.deduplication.collapsed} duplicatas de scan colapsadas)`}
              </span>
            )}
          </div>

          <div className="mt-4 pt-4 border-t border-white/[0.05]">
            <ScopeNote>{data.disclaimer}</ScopeNote>
          </div>
        </div>
      </Panel>

      {/* Frameworks */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {frameworks.map(fw => (
          <FrameworkCard
            key={fw.key}
            fw={fw}
            familyLabels={data.family_labels}
            expanded={expanded === fw.key}
            onToggle={() => setExpanded(e => (e === fw.key ? null : fw.key))}
            onCreateAction={added[fw.key] ? () => onToast?.('success', 'Já adicionado') : createGapAction}
          />
        ))}
      </div>
    </div>
  );
}
