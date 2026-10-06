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
 * Aba Radar — notícias de segurança e timeline regulatória.
 *
 * Tudo aqui vem de fonte autoritativa (CISA, NVD) ou de uma tabela curada com
 * link oficial. Nada é gerado por IA: o modelo tem corte de conhecimento e
 * inventaria datas e fatos se perguntado por "últimas notícias".
 */

import React, { useState, useEffect } from 'react';
import {
  Radar, ExternalLink, ShieldAlert, Scale, Clock, WifiOff, RefreshCw,
} from 'lucide-react';
import { Panel, Spinner, ErrorBanner, EmptyState, ScopeNote, jget, API } from '../ui';

function relDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d)) return String(iso).slice(0, 10);
  const days = Math.floor((Date.now() - d) / 86400000);
  if (days === 0) return 'hoje';
  if (days === 1) return 'ontem';
  if (days < 30) return `há ${days} dias`;
  if (days < 365) return `há ${Math.floor(days / 30)} meses`;
  return d.toLocaleDateString('pt-BR');
}

export default function RadarTab({ onToast }) {
  const [feeds, setFeeds] = useState(null);
  const [reg, setReg] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const load = async (force = false) => {
    setLoading(true);
    setError(null);
    try {
      const [f, r] = await Promise.all([
        jget(`/posture/feeds?limit=20${force ? '&force=true' : ''}`),
        jget('/posture/regulatory'),
      ]);
      setFeeds(f);
      setReg(r);
      if (force) onToast?.('success', 'Radar atualizado');
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  if (loading && !feeds) return <Spinner label="Consultando CISA e NVD..." />;
  if (error) return <ErrorBanner message={error} />;

  const kev = feeds?.kev;

  return (
    <div className="flex flex-col gap-5">
      {/* Alerta KEV — o radar mudando o score, não só enfeitando */}
      {kev?.your_match_count > 0 && (
        <div className="rounded-2xl border border-rose-500/30 bg-gradient-to-b from-rose-950/40 to-[#060b13]/60 overflow-hidden">
          <div className="h-[2px] w-full bg-gradient-to-r from-rose-500 to-orange-500/40" />
          <div className="p-5 flex items-start gap-4">
            <div className="w-10 h-10 rounded-xl bg-rose-500/15 border border-rose-500/25 flex items-center justify-center shrink-0">
              <ShieldAlert className="w-5 h-5 text-rose-400" />
            </div>
            <div className="min-w-0">
              <p className="text-sm font-bold text-rose-300">
                {kev.your_match_count} CVE{kev.your_match_count !== 1 ? 's' : ''} sob exploração ativa
              </p>
              <p className="text-xs text-gray-400 mt-1 leading-relaxed">
                Consta no catálogo <span className="font-semibold text-rose-300">Known Exploited
                Vulnerabilities</span> da CISA — exploração confirmada em campo, não teórica.
                Estes findings recebem peso maior no cálculo de risco.
              </p>
              <div className="flex flex-wrap gap-1.5 mt-2.5">
                {kev.your_matches.map(cve => (
                  <a
                    key={cve}
                    href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                    target="_blank" rel="noopener noreferrer"
                    className="text-[11px] font-mono text-rose-300 bg-rose-500/10 border border-rose-500/25 px-2 py-0.5 rounded-md hover:bg-rose-500/20 transition-colors flex items-center gap-1"
                  >
                    {cve} <ExternalLink className="w-2.5 h-2.5" />
                  </a>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {feeds?.degraded && (
        <div className="flex items-center gap-3 px-4 py-3 rounded-xl bg-amber-500/[0.07] border border-amber-500/20 text-xs text-amber-400">
          <WifiOff className="w-4 h-4 shrink-0" />
          <span>
            Fontes externas parcialmente indisponíveis ({feeds.errors?.join('; ')}).
            Exibindo o último conteúdo em cache.
          </span>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Notícias */}
        <Panel
          title="Radar de ameaças"
          icon={<Radar className="w-4 h-4 text-cyan-400" />}
          accent="from-cyan-500/50 to-blue-500/25"
          right={
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-gray-600">
                {feeds?.cache?.status === 'fresh' ? 'atualizado' : feeds?.cache?.status}
              </span>
              <button
                onClick={() => load(true)}
                disabled={loading}
                className="p-1.5 rounded-lg text-gray-600 hover:text-white hover:bg-white/5 transition-all"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              </button>
            </div>
          }
        >
          {!feeds?.items?.length ? (
            <EmptyState
              icon={<WifiOff className="w-5 h-5 text-gray-600" />}
              title="Sem itens no radar"
              subtitle="As fontes externas não responderam e não há cache disponível."
            />
          ) : (
            <div className="max-h-[560px] overflow-y-auto">
              {feeds.items.map((it, i) => (
                <a
                  key={`${it.source}-${it.title}-${i}`}
                  href={it.url} target="_blank" rel="noopener noreferrer"
                  className="block px-4 py-3 border-b border-white/[0.04] last:border-0 hover:bg-white/[0.025] transition-colors group"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${
                          it.source === 'CISA'
                            ? 'text-orange-300 bg-orange-500/10 border-orange-500/25'
                            : 'text-blue-300 bg-blue-500/10 border-blue-500/25'
                        }`}>
                          {it.source}
                        </span>
                        <span className="text-[10px] text-gray-600">{relDate(it.published_at)}</span>
                        {it.cvss_score && (
                          <span className="text-[10px] font-bold text-rose-400">CVSS {it.cvss_score}</span>
                        )}
                      </div>
                      <p className="text-xs font-medium text-gray-300 group-hover:text-white transition-colors leading-snug">
                        {it.title}
                      </p>
                      {it.summary && (
                        <p className="text-[11px] text-gray-600 mt-1 leading-relaxed line-clamp-2">
                          {it.summary}
                        </p>
                      )}
                    </div>
                    <ExternalLink className="w-3 h-3 text-gray-700 group-hover:text-gray-400 shrink-0 mt-1" />
                  </div>
                </a>
              ))}
            </div>
          )}
        </Panel>

        {/* Timeline regulatória */}
        <Panel
          title="Radar regulatório"
          icon={<Scale className="w-4 h-4 text-amber-400" />}
          accent="from-amber-500/50 to-orange-500/25"
          right={
            reg && (
              <span className="text-[10px] text-amber-400 font-bold">
                {reg.applicable_count} de {reg.total} aplicáveis
              </span>
            )
          }
        >
          <div className="max-h-[560px] overflow-y-auto">
            {(reg?.timeline || []).map(t => (
              <div
                key={t.id}
                className={`px-4 py-3 border-b border-white/[0.04] last:border-0 ${
                  t.applies_to_you ? 'bg-amber-500/[0.03]' : ''
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <span className="text-[9px] font-bold px-1.5 py-0.5 rounded border text-gray-400 bg-white/[0.04] border-white/[0.08]">
                        {t.jurisdiction}
                      </span>
                      <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${
                        t.status === 'in_force'
                          ? 'text-emerald-300 bg-emerald-500/10 border-emerald-500/25'
                          : 'text-blue-300 bg-blue-500/10 border-blue-500/25'
                      }`}>
                        {t.status === 'in_force' ? 'em vigor' : 'futuro'}
                      </span>
                      {t.applies_to_you && (
                        <span className="text-[9px] font-bold px-1.5 py-0.5 rounded border text-amber-300 bg-amber-500/10 border-amber-500/25">
                          aplica a você
                        </span>
                      )}
                    </div>
                    <p className="text-xs font-medium text-gray-300 leading-snug">{t.title}</p>
                    <p className="text-[11px] text-gray-600 mt-1 leading-relaxed">{t.summary}</p>
                    <div className="flex items-center gap-3 mt-1.5">
                      <span className="text-[10px] text-gray-600 flex items-center gap-1">
                        <Clock className="w-2.5 h-2.5" />
                        {t.effective_date}
                        {t.days_until_effective > 0 && ` (em ${t.days_until_effective} dias)`}
                      </span>
                      {t.applies_to_you && (
                        <span className="text-[10px] text-amber-400/80">
                          {t.impacted_families_with_findings.length} área
                          {t.impacted_families_with_findings.length !== 1 ? 's' : ''} com findings
                        </span>
                      )}
                    </div>
                  </div>
                  <a href={t.url} target="_blank" rel="noopener noreferrer"
                     className="text-gray-700 hover:text-gray-400 shrink-0 mt-1">
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              </div>
            ))}
          </div>
          {reg?.note && (
            <div className="px-4 py-3 bg-[#030710]/40 border-t border-white/[0.04]">
              <ScopeNote>{reg.note}</ScopeNote>
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}
