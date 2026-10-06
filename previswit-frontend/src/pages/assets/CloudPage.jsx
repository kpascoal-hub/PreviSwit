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
 * PreviSwit AI-ASPM — Cloud Security & IaC (CSPM)
 * ================================================
 * Módulo dedicado à postura de segurança em ambientes cloud e
 * análise estática de Infraestrutura como Código (IaC).
 *
 * Estrutura:
 *   - Cabeçalho executivo com breadcrumb
 *   - 3 Cards de Cloud Provider (AWS, Azure, GCP) com status de integração
 *   - Painel de ação: Scan IaC com seleção de repositório
 *   - DataGrid: Tabela de má-configurações detectadas
 *   - Hidratação via localStorage (previswit_iac_<target>)
 *
 * Regra: ZERO mocks. Tudo vem dos endpoints reais do backend.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { NavLink } from 'react-router-dom';
import {
  ArrowLeft, Cloud, Shield, AlertTriangle, RefreshCw,
  Terminal, ChevronDown, CheckCircle, Server,
  Lock, Unlock, Activity, Search, ExternalLink,
  FileText, Zap, Database, Eye, ChevronRight,
  Box, Globe, Layers, HardDrive, Settings,
  TrendingUp, Code2, BrainCircuit, Loader2, Trash2
} from 'lucide-react';

const API = '/api/v1';

// ── Helpers ──────────────────────────────────────────────────────────────────

function severityColor(sev) {
  const s = (sev || '').toUpperCase();
  if (s === 'CRITICAL') return { bg: 'bg-rose-500/10', text: 'text-rose-400', border: 'border-rose-500/25', dot: 'bg-rose-500' };
  if (s === 'HIGH')     return { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/25', dot: 'bg-red-500' };
  if (s === 'MEDIUM')   return { bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/25', dot: 'bg-amber-500' };
  if (s === 'LOW')      return { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/25', dot: 'bg-blue-500' };
  if (s === 'FAILED')   return { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/25', dot: 'bg-red-500' };
  return { bg: 'bg-gray-500/10', text: 'text-gray-400', border: 'border-gray-500/25', dot: 'bg-gray-500' };
}

function providerIcon(id) {
  if (id === 'aws') return (
    <svg viewBox="0 0 24 24" className="w-6 h-6" fill="none">
      <path d="M7.16 14.58c0 .27.03.49.08.65.06.16.13.34.23.53.04.06.05.12.05.17 0 .07-.05.15-.14.22l-.47.31c-.07.04-.13.07-.19.07-.07 0-.15-.04-.22-.11a2.26 2.26 0 01-.26-.34 5.66 5.66 0 01-.22-.43c-.56.66-1.27.99-2.11.99-.6 0-1.08-.17-1.43-.52-.35-.34-.53-.8-.53-1.37 0-.6.21-1.09.64-1.46.43-.37 1-.55 1.73-.55.24 0 .49.02.75.06.26.04.53.1.82.17v-.52c0-.54-.11-.92-.34-1.14-.22-.22-.61-.33-1.15-.33-.25 0-.5.03-.77.09-.27.06-.53.14-.79.24a2.11 2.11 0 01-.25.09c-.04 0-.07-.03-.07-.1v-.36c0-.07.01-.13.04-.16a.43.43 0 01.15-.1c.25-.13.56-.24.92-.33.36-.09.74-.14 1.15-.14.87 0 1.51.2 1.92.6.4.4.61 1.01.61 1.83v2.41zm-2.92 1.09c.23 0 .47-.04.72-.13.25-.08.47-.24.66-.45a1 1 0 00.23-.44c.04-.16.07-.36.07-.59v-.28c-.21-.06-.44-.1-.67-.14-.24-.03-.47-.05-.69-.05-.47 0-.82.09-1.05.29-.23.19-.34.46-.34.82 0 .33.09.58.27.75.17.18.42.26.75.26l.05-.04zm5.78.75c-.09 0-.16-.02-.2-.06-.04-.03-.08-.11-.12-.22L8.13 11.5c-.04-.12-.06-.2-.06-.24 0-.08.04-.13.13-.13h.73c.1 0 .16.02.2.06.04.03.08.11.11.22l1.13 4.45 1.05-4.45c.03-.12.07-.19.11-.22.05-.04.12-.06.21-.06h.6c.1 0 .17.02.21.06.04.03.08.11.11.22l1.06 4.51 1.16-4.51c.03-.12.07-.19.12-.22a.33.33 0 01.2-.06h.69c.09 0 .14.04.14.13 0 .03 0 .05-.01.09-.01.03-.02.08-.05.15l-1.72 4.64c-.04.12-.08.19-.12.22-.04.04-.11.06-.2.06h-.64c-.1 0-.17-.02-.21-.06-.04-.04-.08-.11-.11-.23l-1.04-4.34-1.04 4.33c-.03.12-.07.2-.11.23-.04.04-.12.06-.21.06h-.64v.01zm9.25.26c-.37 0-.73-.04-1.08-.13-.35-.09-.62-.18-.8-.29a.46.46 0 01-.14-.14.36.36 0 01-.03-.14v-.38c0-.07.03-.1.08-.1.02 0 .05 0 .07.02.03.01.06.03.1.06.32.16.67.28 1.04.37.38.09.74.13 1.12.13.59 0 1.05-.1 1.37-.32.32-.21.49-.52.49-.93 0-.27-.09-.5-.26-.67a1.73 1.73 0 00-.85-.5l-1.22-.38c-.61-.19-1.06-.48-1.34-.86a2.04 2.04 0 01-.41-1.22c0-.35.08-.66.23-.93.15-.27.35-.5.61-.69.26-.19.55-.33.89-.43.34-.1.7-.14 1.07-.14.19 0 .39.01.58.04.2.03.38.07.57.11.18.05.35.1.51.16.16.06.28.12.37.18.12.07.21.15.26.22.05.07.07.16.07.28v.35c0 .07-.03.11-.08.11a.38.38 0 01-.17-.07 4.07 4.07 0 00-1.77-.37c-.54 0-.96.08-1.26.25-.3.17-.45.44-.45.82 0 .27.1.51.28.69.19.19.54.37 1.05.54l1.2.38c.6.19 1.04.46 1.3.81.27.35.4.75.4 1.19 0 .36-.07.69-.22.98-.15.29-.36.55-.63.75-.27.21-.59.36-.96.47-.38.11-.79.17-1.22.17z" fill="#FF9900"/>
      <path d="M21.37 18.31c-2.62 1.94-6.43 2.97-9.7 2.97-4.59 0-8.72-1.7-11.84-4.52-.25-.22-.02-.53.27-.35 3.37 1.96 7.54 3.14 11.85 3.14 2.9 0 6.1-.6 9.04-1.85.44-.19.82.29.38.61z" fill="#FF9900"/>
      <path d="M22.49 17.03c-.34-.43-2.22-.2-3.07-.1-.26.03-.3-.19-.07-.36 1.5-1.06 3.97-.75 4.26-.4.29.36-.08 2.84-1.49 4.02-.22.18-.42.08-.33-.15.32-.79 1.04-2.58.7-3.01z" fill="#FF9900"/>
    </svg>
  );
  if (id === 'azure') return (
    <svg viewBox="0 0 24 24" className="w-6 h-6" fill="none">
      <path d="M8.84 3.04L3 17.18h4.12L13.46 3.04H8.84zm3.57 2.23l-3.44 8.97 6.72 7.72h5.31l-6.73-7.72 4.87-8.97h-6.73z" fill="#0089D6"/>
    </svg>
  );
  if (id === 'gcp') return (
    <svg viewBox="0 0 24 24" className="w-6 h-6" fill="none">
      <path d="M15.55 8.44l1.79-1.79.09-.75a8.77 8.77 0 00-14.27 4.34l.65-.09 3.57-.59.27-.28A4.89 4.89 0 0112 7.12c1.37 0 2.61.56 3.55 1.32z" fill="#EA4335"/>
      <path d="M19.63 10.24a8.79 8.79 0 00-2.29-3.59l-2.51 2.51A4.88 4.88 0 0116.88 12c0 .68-.14 1.32-.38 1.91l2.51 2.51a8.73 8.73 0 00.62-6.18z" fill="#4285F4"/>
      <path d="M12 16.88c-1.37 0-2.6-.56-3.55-1.32l-2.51 2.51A8.76 8.76 0 0012 20.77c2.12 0 4.07-.75 5.61-2.01l-2.51-2.51A4.88 4.88 0 0112 16.88z" fill="#34A853"/>
      <path d="M7.12 12c0-.68.14-1.32.38-1.91l-2.51-2.51A8.73 8.73 0 003.23 12a8.73 8.73 0 001.76 4.42l2.51-2.51A4.88 4.88 0 017.12 12z" fill="#FBBC05"/>
    </svg>
  );
  return <Cloud className="w-6 h-6 text-gray-500" />;
}

// ── Cloud Provider Card ──────────────────────────────────────────────────────

function ProviderCard({ provider }) {
  const connected = provider.status === 'connected';
  const score = provider.compliance_score;

  return (
    <div className={`relative flex flex-col rounded-2xl border overflow-hidden transition-all duration-300
                     ${connected
                       ? 'bg-gradient-to-b from-[#0d1421]/80 to-[#060b13]/90 border-emerald-500/20 hover:border-emerald-500/40'
                       : 'bg-gradient-to-b from-[#0d1421]/60 to-[#060b13]/80 border-white/[0.06] hover:border-white/[0.12]'
                     }`}
    >
      {/* Accent line */}
      <div className={`h-[2px] w-full ${connected ? 'bg-gradient-to-r from-emerald-500/60 to-teal-500/30' : 'bg-gradient-to-r from-white/5 to-white/0'}`} />

      <div className="p-5 flex flex-col gap-4">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-xl border flex items-center justify-center
                            ${connected ? 'bg-emerald-500/10 border-emerald-500/20' : 'bg-white/[0.04] border-white/[0.08]'}`}>
              {providerIcon(provider.id)}
            </div>
            <div>
              <p className="text-sm font-bold text-white">{provider.name}</p>
              <p className="text-[10px] text-gray-600 mt-0.5">{provider.services_supported?.slice(0, 3).join(' · ')}</p>
            </div>
          </div>

          <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-[10px] font-bold tracking-wide
                          ${connected
                            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/25'
                            : 'bg-white/[0.04] text-gray-500 border-white/[0.08]'
                          }`}>
            <span className={`w-1.5 h-1.5 rounded-full ${connected ? 'bg-emerald-400 animate-pulse' : 'bg-gray-600'}`} />
            {connected ? 'Conectado' : 'Desconectado'}
          </div>
        </div>

        {/* Compliance Score */}
        <div className="bg-white/[0.03] border border-white/[0.05] rounded-xl p-3">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold">Conformidade</span>
            <span className={`text-xs font-bold ${score ? (score >= 80 ? 'text-emerald-400' : score >= 50 ? 'text-amber-400' : 'text-red-400') : 'text-gray-600'}`}>
              {score != null ? `${score}%` : '—'}
            </span>
          </div>
          <div className="w-full h-1.5 rounded-full bg-white/[0.06] overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-500 ${
                score ? (score >= 80 ? 'bg-emerald-500' : score >= 50 ? 'bg-amber-500' : 'bg-red-500') : 'bg-transparent'
              }`}
              style={{ width: score != null ? `${score}%` : '0%' }}
            />
          </div>
        </div>

        {/* Action */}
        <button
          disabled={!connected}
          className="w-full flex items-center justify-center gap-1.5 py-2 text-xs font-semibold rounded-xl
                     border border-white/[0.08] bg-white/[0.03] text-gray-500
                     hover:bg-white/[0.07] hover:text-gray-300 hover:border-white/15 transition-all duration-150
                     disabled:opacity-30 disabled:cursor-not-allowed"
        >
          <Settings className="w-3 h-3" />
          Configurar
        </button>
      </div>
    </div>
  );
}


// ── Misconfiguration Row ─────────────────────────────────────────────────────

function MisconfigRow({ item, index }) {
  const sev = severityColor(item.severity);
  const [expanded, setExpanded] = useState(false);
  const [aiText, setAiText] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);

  const handleToggle = () => {
    const next = !expanded;
    setExpanded(next);
    if (next && aiText === null && !aiLoading) {
      const geminiKey = sessionStorage.getItem('gemini_api_key') || sessionStorage.getItem('GEMINI_KEY') || sessionStorage.getItem('gemini_key');
      if (!geminiKey) return;
      setAiLoading(true);
      const prompt = `Você é um especialista em segurança de nuvem e IaC (Infraestrutura como Código).
Analise a seguinte má-configuração detectada pelo Checkov/Trivy e responda EXCLUSIVAMENTE em português brasileiro.

**ID do Check:** ${item.id || 'N/A'}
**Má-configuração:** ${item.misconfiguration}
**Severidade:** ${item.severity || 'N/A'}
**Framework:** ${item.framework || 'N/A'}
**Recurso afetado:** ${item.resource || 'N/A'}
${item.resolution ? `**Resolução (en):** ${item.resolution}` : ''}

Responda com:
1. **O que é:** Explique o problema em 1-2 frases simples em português.
2. **Por que é perigoso:** Descreva o risco concreto de segurança.
3. **Como corrigir:** Passos práticos de remediação para ${item.framework || 'IaC'}.

Seja direto e técnico. Máximo 150 palavras no total.`;

      fetch('/api/v1/ai/insight', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Gemini-Key': geminiKey },
        body: JSON.stringify({ prompt }),
      })
        .then(r => r.json())
        .then(d => setAiText(d.response || '⚠️ Sem resposta da IA.'))
        .catch(() => setAiText('⚠️ Erro ao consultar IA.'))
        .finally(() => setAiLoading(false));
    }
  };

  return (
    <div className="group">
      <div
        onClick={handleToggle}
        className={`grid grid-cols-12 gap-3 items-center px-4 py-3 cursor-pointer
                    border-b border-white/[0.04] hover:bg-white/[0.03] transition-all duration-150
                    ${index % 2 === 0 ? 'bg-transparent' : 'bg-white/[0.01]'}`}
      >
        {/* # */}
        <div className="col-span-1 text-[11px] text-gray-600 font-mono">
          #{String(index + 1).padStart(3, '0')}
        </div>

        {/* Resource */}
        <div className="col-span-3 flex items-center gap-2 min-w-0">
          <div className="w-6 h-6 rounded-lg bg-white/[0.04] border border-white/[0.06] flex items-center justify-center shrink-0">
            <Layers className="w-3 h-3 text-gray-500" />
          </div>
          <div className="min-w-0">
            <p className="text-xs font-medium text-gray-300 truncate">{item.resource}</p>
            {item.file_path && (
              <p className="text-[10px] text-gray-600 truncate mt-0.5">{item.file_path}</p>
            )}
          </div>
        </div>

        {/* Misconfiguration */}
        <div className="col-span-4 min-w-0">
          <p className="text-xs text-gray-400 truncate">{item.misconfiguration}</p>
          {item.id && item.id !== 'N/A' && (
            <p className="text-[10px] text-gray-600 font-mono mt-0.5">{item.id}</p>
          )}
        </div>

        {/* Severity */}
        <div className="col-span-2">
          <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-[10px] font-bold tracking-wide ${sev.bg} ${sev.text} ${sev.border}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${sev.dot}`} />
            {(item.severity || 'N/A').toUpperCase()}
          </span>
        </div>

        {/* Framework */}
        <div className="col-span-2 flex items-center justify-between">
          <span className="text-[10px] text-gray-600 bg-white/[0.04] border border-white/[0.06] px-2 py-0.5 rounded-md">
            {item.framework || '—'}
          </span>
          <ChevronRight className={`w-3 h-3 text-gray-600 transition-transform duration-200 ${expanded ? 'rotate-90' : ''}`} />
        </div>
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div className="px-4 py-3 bg-[#060b13]/60 border-b border-white/[0.04]">
          <div className="grid grid-cols-2 gap-4 text-xs">
            {item.guideline && (
              <div>
                <p className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold mb-1">Guideline</p>
                <a href={item.guideline} target="_blank" rel="noopener noreferrer"
                   className="text-blue-400 hover:text-blue-300 flex items-center gap-1 transition-colors">
                  <ExternalLink className="w-3 h-3" /> Documentação
                </a>
              </div>
            )}
            {item.resolution && (
              <div>
                <p className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold mb-1">Resolução</p>
                <p className="text-gray-400 leading-relaxed">{item.resolution}</p>
              </div>
            )}
            {item.primary_url && (
              <div>
                <p className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold mb-1">Referência</p>
                <a href={item.primary_url} target="_blank" rel="noopener noreferrer"
                   className="text-blue-400 hover:text-blue-300 flex items-center gap-1 transition-colors">
                  <ExternalLink className="w-3 h-3" /> Detalhes
                </a>
              </div>
            )}
            {item.file_path && (
              <div>
                <p className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold mb-1">Arquivo</p>
                <p className="text-gray-400 font-mono">{item.file_path}
                  {item.file_line?.length > 0 && <span className="text-gray-600"> :L{item.file_line.join('-')}</span>}
                </p>
              </div>
            )}
          </div>

          {/* AI Translation panel */}
          {(aiLoading || aiText) && (
            <div className="mt-3 rounded-xl border border-purple-500/20 bg-purple-500/5 p-3">
              <p className="text-[10px] text-purple-400 uppercase tracking-wider font-semibold mb-2 flex items-center gap-1.5">
                <BrainCircuit className="w-3 h-3" /> Análise IA — Português
              </p>
              {aiLoading ? (
                <div className="flex items-center gap-2 text-xs text-gray-500">
                  <Loader2 className="w-3 h-3 animate-spin" /> Consultando Gemini...
                </div>
              ) : (
                <p className="text-xs text-gray-300 leading-relaxed whitespace-pre-wrap">{aiText}</p>
              )}
            </div>
          )}

          {/* Prompt to configure Gemini if key is missing */}
          {!aiLoading && aiText === null && !sessionStorage.getItem('gemini_api_key') && !sessionStorage.getItem('GEMINI_KEY') && !sessionStorage.getItem('gemini_key') && (
            <p className="mt-2 text-[10px] text-gray-600 flex items-center gap-1">
              <BrainCircuit className="w-3 h-3" /> Configure a chave Gemini em Integrações para ver a análise em português.
            </p>
          )}
        </div>
      )}
    </div>
  );
}


// ── Main Page ─────────────────────────────────────────────────────────────────

export default function CloudPage() {
  // State
  const [providers, setProviders] = useState([]);
  const [loading, setLoading] = useState(true);
  const [scanTarget, setScanTarget] = useState('');
  const [scanStatus, setScanStatus] = useState(null); // null | 'PENDING' | 'RUNNING' | 'CONCLUÍDO' | 'ERROR'
  const [scanId, setScanId] = useState(null);
  const [scanData, setScanData] = useState(null);
  const [scanError, setScanError] = useState(null);
  const [toast, setToast] = useState(null);

  const showToast = (msg) => {
    setToast(msg);
    setTimeout(() => setToast(null), 3500);
  };

  // ── Fetch Providers ───────────────────────────────────────────────────────
  const fetchProviders = useCallback(async () => {
    try {
      const res = await fetch(`${API}/cloud/providers`);
      if (res.ok) {
        const data = await res.json();
        setProviders(data.providers || []);
      }
    } catch (e) {
      console.error('Erro ao carregar providers:', e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchProviders(); }, [fetchProviders]);

  // ── Hidratação do último scan via localStorage ────────────────────────────
  useEffect(() => {
    const lastScan = localStorage.getItem('previswit_iac_last');
    if (lastScan) {
      try {
        const parsed = JSON.parse(lastScan);
        setScanData(parsed.data);
        setScanStatus('CONCLUÍDO');
        setScanTarget(parsed.target || '');
      } catch (e) { /* ignora */ }
    }
  }, []);

  // ── Polling de Scan IaC ───────────────────────────────────────────────────
  useEffect(() => {
    let interval;
    if (scanId && (scanStatus === 'PENDING' || scanStatus === 'RUNNING')) {
      interval = setInterval(async () => {
        try {
          const res = await fetch(`${API}/cloud/iac-scan-status/${scanId}`);
          if (res.ok) {
            const data = await res.json();
            setScanStatus(data.status);
            if (data.status === 'CONCLUÍDO') {
              setScanData(data.data);
              localStorage.setItem('previswit_iac_last', JSON.stringify({
                target: scanTarget,
                data: data.data,
                ts: new Date().toISOString(),
              }));
              showToast('Scan IaC concluído com sucesso');
              clearInterval(interval);
            } else if (data.status === 'ERROR') {
              setScanError(data.error);
              showToast('Erro no scan IaC');
              clearInterval(interval);
            }
          }
        } catch (e) {
          console.error('Polling error:', e);
        }
      }, 3000);
    }
    return () => clearInterval(interval);
  }, [scanId, scanStatus]);

  // ── Iniciar Scan IaC ──────────────────────────────────────────────────────
  const handleStartScan = async () => {
    if (!scanTarget.trim()) {
      showToast('Informe uma URL de repositório ou caminho local');
      return;
    }

    setScanStatus('PENDING');
    setScanData(null);
    setScanError(null);

    try {
      const isUrl = scanTarget.startsWith('http') || scanTarget.startsWith('git@');
      const res = await fetch(`${API}/cloud/iac-scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repo_url: isUrl ? scanTarget : '',
          local_path: isUrl ? '' : scanTarget,
          target_name: scanTarget.split('/').pop() || scanTarget,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        setScanId(data.scan_id);
        showToast('Scan IaC iniciado');
      } else {
        setScanStatus('ERROR');
        showToast('Falha ao iniciar scan');
      }
    } catch (e) {
      setScanStatus('ERROR');
      showToast('Erro de conexão com o backend');
    }
  };

  // ── Limpar último scan ────────────────────────────────────────────────────
  const handleClearScan = () => {
    localStorage.removeItem('previswit_iac_last');
    setScanData(null);
    setScanStatus(null);
    setScanTarget('');
    setScanId(null);
    setScanError(null);
    showToast('Registros de má-configurações removidos');
  };

  // ── Computed ──────────────────────────────────────────────────────────────
  const misconfigs = scanData?.misconfigurations || [];
  const stats = scanData?.stats || {};
  const isScanning = scanStatus === 'PENDING' || scanStatus === 'RUNNING';
  const isConcluded = scanStatus === 'CONCLUÍDO';
  const criticalCount = misconfigs.filter(m => (m.severity || '').toUpperCase() === 'CRITICAL').length;
  const highCount = misconfigs.filter(m => (m.severity || '').toUpperCase() === 'HIGH').length;
  const mediumCount = misconfigs.filter(m => (m.severity || '').toUpperCase() === 'MEDIUM').length;
  const lowCount = misconfigs.filter(m => (m.severity || '').toUpperCase() === 'LOW' || (m.severity || '').toUpperCase() === 'INFO').length;

  return (
    <section id="view-cloud" className="view-section w-full flex flex-col gap-6">

      {/* ── Header ───────────────────────────────────────────────────────── */}
      <div className="flex items-start justify-between gap-4">
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-1.5">
            <NavLink
              to="/assets"
              className="text-xs text-gray-600 hover:text-gray-400 flex items-center gap-1 transition-colors"
            >
              <ArrowLeft className="w-3 h-3" />
              Ativos &amp; Produtos
            </NavLink>
            <span className="text-gray-700">/</span>
            <span className="text-xs text-sky-400 font-medium">Cloud Security</span>
          </div>
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2.5">
              <Shield className="w-5 h-5 text-sky-400" />
              Cloud Security &amp; IaC
            </h1>
            <p className="text-sm text-gray-500 mt-0.5">
              CSPM · Análise de Má-Configurações · Infraestrutura como Código
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={fetchProviders}
            disabled={loading}
            className="p-2 rounded-lg border border-white/[0.08] text-gray-500 hover:text-white
                       hover:bg-white/5 hover:border-white/20 transition-all disabled:opacity-40"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* ── Provider Cards ───────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {(providers.length > 0 ? providers : [
          { id: 'aws', name: 'Amazon Web Services', status: 'disconnected', services_supported: ['EC2', 'S3', 'IAM'], compliance_score: null },
          { id: 'azure', name: 'Microsoft Azure', status: 'disconnected', services_supported: ['VMs', 'Blob', 'AKS'], compliance_score: null },
          { id: 'gcp', name: 'Google Cloud Platform', status: 'disconnected', services_supported: ['GCE', 'GCS', 'GKE'], compliance_score: null },
        ]).map(p => (
          <ProviderCard key={p.id} provider={p} />
        ))}
      </div>

      {/* ── IaC Scan Panel ───────────────────────────────────────────────── */}
      <div className="bg-gradient-to-b from-[#0d1421]/80 to-[#060b13]/90 border border-white/[0.06] rounded-2xl overflow-hidden">
        <div className="h-[2px] w-full bg-gradient-to-r from-sky-500/50 to-purple-500/30" />

        <div className="p-6">
          <div className="flex items-center gap-3 mb-5">
            <div className="w-9 h-9 rounded-xl bg-sky-500/10 border border-sky-500/20 flex items-center justify-center">
              <Terminal className="w-4 h-4 text-sky-400" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white">Análise de Infraestrutura (IaC)</h2>
              <p className="text-[11px] text-gray-500 mt-0.5">Checkov + Trivy Config · Terraform, Kubernetes, Dockerfile, ARM, CloudFormation</p>
            </div>
          </div>

          {/* Input + Action */}
          <div className="flex gap-3">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-600" />
              <input
                type="text"
                value={scanTarget}
                onChange={(e) => setScanTarget(e.target.value)}
                placeholder="https://github.com/org/repo.git ou /caminho/local/do/projeto"
                className="w-full bg-[#111827] border border-white/[0.08] rounded-xl pl-10 pr-4 py-2.5 text-sm text-white
                           placeholder:text-gray-600 focus:outline-none focus:border-sky-500/40 focus:ring-1 focus:ring-sky-500/20 transition-all"
              />
            </div>
            <button
              onClick={handleStartScan}
              disabled={isScanning || !scanTarget.trim()}
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold
                         bg-sky-600 hover:bg-sky-500 text-white shadow-lg shadow-sky-500/20
                         transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isScanning
                ? <><span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Analisando...</>
                : <><Search className="w-4 h-4" /> Iniciar Scan IaC</>
              }
            </button>
          </div>

          {/* Scan Error */}
          {scanStatus === 'ERROR' && scanError && (
            <div className="mt-4 flex items-center gap-3 px-4 py-3 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{scanError}</span>
            </div>
          )}
        </div>
      </div>

      {/* ── KPI Strip (pós-scan) ─────────────────────────────────────────── */}
      {isConcluded && (
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          {[
            { label: 'Total', value: misconfigs.length, color: 'text-white', icon: <Database className="w-4 h-4 text-sky-400" />, accent: 'border-sky-500/15' },
            { label: 'Critical', value: criticalCount, color: 'text-rose-400', icon: <AlertTriangle className="w-4 h-4 text-rose-400" />, accent: 'border-rose-500/15' },
            { label: 'High', value: highCount, color: 'text-red-400', icon: <TrendingUp className="w-4 h-4 text-red-400" />, accent: 'border-red-500/15' },
            { label: 'Medium', value: mediumCount, color: 'text-amber-400', icon: <Activity className="w-4 h-4 text-amber-400" />, accent: 'border-amber-500/15' },
            { label: 'Low / Info', value: lowCount, color: 'text-blue-400', icon: <Shield className="w-4 h-4 text-blue-400" />, accent: 'border-blue-500/15' },
          ].map(stat => (
            <div
              key={stat.label}
              className={`bg-gradient-to-b from-[#0d1421]/70 to-[#060b13]/60 border ${stat.accent} rounded-2xl p-4 flex items-center gap-3 transition-all duration-200`}
            >
              <div className="w-9 h-9 rounded-xl bg-white/[0.04] border border-white/[0.06] flex items-center justify-center shrink-0">
                {stat.icon}
              </div>
              <div>
                <p className="text-[10px] text-gray-600 uppercase tracking-wider font-semibold">{stat.label}</p>
                <p className={`text-2xl font-bold mt-0.5 ${stat.color} leading-none`}>{stat.value}</p>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ── DataGrid: Misconfigurations Table ────────────────────────────── */}
      {isConcluded && (
        <div className="bg-gradient-to-b from-[#0d1421]/80 to-[#060b13]/90 border border-white/[0.06] rounded-2xl overflow-hidden">
          {/* Table header */}
          <div className="px-5 py-4 border-b border-white/[0.05] flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <span className="w-1 h-5 rounded-full bg-sky-500/60" />
              <h3 className="text-sm font-bold text-white">
                Má-Configurações Detectadas
              </h3>
              <span className="text-[10px] text-gray-500 bg-white/[0.04] border border-white/[0.06] px-2 py-0.5 rounded-md">
                {misconfigs.length} encontrada{misconfigs.length !== 1 ? 's' : ''}
              </span>
              <button
                onClick={handleClearScan}
                title="Limpar resultados"
                className="p-1.5 rounded-lg text-gray-600 hover:text-red-400 hover:bg-red-500/10 border border-transparent hover:border-red-500/20 transition-all duration-150"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </div>
            {scanData?.frameworks_detected?.length > 0 && (
              <div className="flex items-center gap-1.5">
                <span className="text-[10px] text-gray-600">Frameworks:</span>
                {scanData.frameworks_detected.map(f => (
                  <span key={f} className="text-[10px] text-sky-400 bg-sky-500/10 border border-sky-500/20 px-2 py-0.5 rounded-md">
                    {f}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Column headers */}
          <div className="grid grid-cols-12 gap-3 px-4 py-2.5 text-[10px] text-gray-500 uppercase tracking-wider font-semibold border-b border-white/[0.04] bg-white/[0.02]">
            <div className="col-span-1">#</div>
            <div className="col-span-3">Recurso</div>
            <div className="col-span-4">Má-Configuração</div>
            <div className="col-span-2">Risco</div>
            <div className="col-span-2">Framework</div>
          </div>

          {/* Rows */}
          <div className="max-h-[500px] overflow-y-auto">
            {misconfigs.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 gap-3">
                <div className="w-12 h-12 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
                  <Shield className="w-5 h-5 text-emerald-400" />
                </div>
                <p className="text-sm font-semibold text-emerald-400">Nenhuma má-configuração detectada</p>
                <p className="text-xs text-gray-600">A infraestrutura analisada está em conformidade.</p>
              </div>
            ) : (
              misconfigs.map((item, i) => (
                <MisconfigRow key={`${item.id}-${i}`} item={item} index={i} />
              ))
            )}
          </div>
        </div>
      )}

      {/* ── Empty state (pré-scan) ───────────────────────────────────────── */}
      {!isConcluded && !isScanning && (
        <div className="flex flex-col items-center justify-center p-16 border border-dashed border-white/[0.06] rounded-2xl bg-gradient-to-b from-[#0d1421]/40 to-transparent">
          <div className="relative mb-6">
            <div className="w-16 h-16 rounded-2xl bg-sky-500/10 border border-sky-500/20 flex items-center justify-center">
              <Layers className="w-7 h-7 text-sky-400/60" />
            </div>
            <div className="absolute -bottom-1 -right-1 w-5 h-5 rounded-full bg-purple-500/20 border border-purple-500/30 flex items-center justify-center">
              <Search className="w-2.5 h-2.5 text-purple-400" />
            </div>
          </div>
          <p className="text-sm font-semibold text-gray-300 text-center">
            Nenhum scan IaC realizado
          </p>
          <p className="text-xs text-gray-600 text-center mt-2 max-w-sm leading-relaxed">
            Cole a URL de um repositório contendo arquivos Terraform, Dockerfile, Kubernetes ou CloudFormation
            e inicie um scan para detectar má-configurações.
          </p>
        </div>
      )}

      {/* ── Scanning progress ────────────────────────────────────────────── */}
      {isScanning && (
        <div className="flex flex-col items-center justify-center py-20 gap-4">
          <div className="relative">
            <div className="w-10 h-10 border-2 border-sky-500/30 rounded-full" />
            <div className="w-10 h-10 border-2 border-sky-500 border-t-transparent rounded-full animate-spin absolute inset-0" />
          </div>
          <div className="text-center">
            <p className="text-sm font-semibold text-white">Analisando Infraestrutura</p>
            <p className="text-xs text-gray-500 mt-1">Checkov + Trivy estão varrendo os arquivos IaC...</p>
          </div>
        </div>
      )}

      {/* ── Toast ────────────────────────────────────────────────────────── */}
      {toast && (
        <div className="fixed bottom-6 right-6 z-[500] flex items-center gap-2 px-4 py-3 rounded-lg shadow-2xl border border-sky-500/30 bg-[#0d1421]/95 backdrop-blur-md text-xs font-medium text-sky-200 animate-in slide-in-from-bottom-2">
          <CheckCircle className="w-4 h-4 text-sky-400 shrink-0" />
          {toast}
        </div>
      )}

    </section>
  );
}
