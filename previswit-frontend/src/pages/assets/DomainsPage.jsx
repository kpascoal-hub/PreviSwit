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
 * PreviSwit AI-ASPM — Domínios & APIs (DAST / Superfície de Ataque)
 * ==================================================================
 * Módulo de análise de superfície de ataque externa: domínios, APIs públicas
 * e endpoints HTTP expostos. Motor: varredura DAST via WebSocket → Agente.
 *
 * Estrutura:
 *   - Header executivo com breadcrumb de navegação
 *   - Painel de gestão de alvos: lista de domínios/APIs cadastrados com badges de status
 *   - Formulário de adição de novo alvo + botão de Iniciar Pentest DAST
 *   - DataGrid: Tabela de Endpoint, Vulnerabilidade, Severidade, Validação da IA
 *   - Console de logs: saída em tempo real do WebSocket
 *   - Hidratação via localStorage (previswit_dast_<targetUrl>)
 *
 * Protocolo WebSocket:
 *   Envio  → { action: "START_SCAN", target: url, pipeline: "dast_api" }
 *   Retorno → { action: "SCAN_RESULT", data: {...} } | { action: "LOG", message: "..." }
 *
 * Regra: ZERO manipulação direta do DOM. Estado via useState/useEffect/useRef.
 */

import React, { useState, useEffect, useRef, useCallback } from 'react';
import { NavLink } from 'react-router-dom';
import {
  ArrowLeft, Globe, Shield, AlertTriangle, CheckCircle,
  Plus, Trash2, Play, ChevronRight, ExternalLink,
  Terminal, Activity, Clock, RefreshCw, TrendingUp,
  Database, Lock, Unlock, Wifi, WifiOff, Search,
  Zap, Eye, BarChart2, X,
} from 'lucide-react';

// ── Helpers ───────────────────────────────────────────────────────────────────

function severityColors(sev) {
  const s = (sev || '').toUpperCase();
  if (s === 'CRITICAL') return { bg: 'bg-rose-500/10', text: 'text-rose-400', border: 'border-rose-500/25', dot: 'bg-rose-500' };
  if (s === 'HIGH')     return { bg: 'bg-red-500/10',  text: 'text-red-400',  border: 'border-red-500/25',  dot: 'bg-red-500' };
  if (s === 'MEDIUM')   return { bg: 'bg-amber-500/10',text: 'text-amber-400',border: 'border-amber-500/25',dot: 'bg-amber-500' };
  if (s === 'LOW')      return { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/25', dot: 'bg-blue-500' };
  if (s === 'INFO')     return { bg: 'bg-slate-500/10',text: 'text-slate-400',border: 'border-slate-500/25',dot: 'bg-slate-500' };
  return                         { bg: 'bg-gray-500/10',text: 'text-gray-400', border: 'border-gray-500/25', dot: 'bg-gray-500' };
}

function normalizeUrl(raw) {
  const s = raw.trim();
  if (!s) return '';
  if (s.startsWith('http://') || s.startsWith('https://')) return s;
  return `https://${s}`;
}

function storageKey(url) {
  return 'previswit_dast_' + url.replace(/[^a-zA-Z0-9]/g, '_');
}

// ── Severity Badge ────────────────────────────────────────────────────────────

function SeverityBadge({ sev }) {
  const c = severityColors(sev);
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-[10px] font-bold tracking-wide ${c.bg} ${c.text} ${c.border}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${c.dot}`} />
      {(sev || 'N/A').toUpperCase()}
    </span>
  );
}

// ── Finding Row ───────────────────────────────────────────────────────────────

function FindingRow({ finding, index }) {
  const [expanded, setExpanded] = useState(false);

  const endpoint    = finding.endpoint || finding.url || finding.host || '—';
  const vuln        = finding.vulnerability || finding.name || finding.title || finding.description || '—';
  const severity    = finding.severity || finding.risk || 'MEDIUM';
  const aiStatus    = finding.ai_validation || finding.status || finding.remediation || 'Aguardando validação';
  const detail      = finding.detail || finding.evidence || finding.raw || '';

  return (
    <div className="group border-b border-white/[0.04] last:border-0">
      <div
        onClick={() => setExpanded(e => !e)}
        className={`grid grid-cols-12 gap-3 items-center px-4 py-3 cursor-pointer
                    hover:bg-white/[0.025] transition-all duration-150
                    ${index % 2 === 0 ? 'bg-transparent' : 'bg-white/[0.01]'}`}
      >
        {/* # */}
        <div className="col-span-1 text-[11px] text-gray-600 font-mono select-none">
          #{String(index + 1).padStart(3, '0')}
        </div>

        {/* Endpoint */}
        <div className="col-span-4 min-w-0 flex items-center gap-2">
          <div className="w-6 h-6 rounded-lg bg-white/[0.04] border border-white/[0.06] flex items-center justify-center shrink-0">
            <Globe className="w-3 h-3 text-gray-500" />
          </div>
          <span className="text-xs font-mono text-gray-300 truncate">{endpoint}</span>
        </div>

        {/* Vulnerability */}
        <div className="col-span-3 min-w-0">
          <p className="text-xs text-gray-400 truncate">{vuln}</p>
        </div>

        {/* Severity */}
        <div className="col-span-2">
          <SeverityBadge sev={severity} />
        </div>

        {/* AI Validation */}
        <div className="col-span-1 flex items-center justify-between gap-1">
          <span className="text-[10px] text-emerald-400 truncate hidden lg:block">{aiStatus}</span>
          <ChevronRight
            className={`w-3.5 h-3.5 text-gray-600 transition-transform duration-200 shrink-0 ${expanded ? 'rotate-90' : ''}`}
          />
        </div>
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div className="px-4 py-4 bg-[#060b13]/70 border-b border-white/[0.04]">
          <div className="grid grid-cols-2 gap-5">
            <div>
              <p className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold mb-1">Endpoint Completo</p>
              <p className="text-xs font-mono text-gray-400 break-all">{endpoint}</p>
            </div>
            <div>
              <p className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold mb-1">Validação IA</p>
              <p className="text-xs text-emerald-400 leading-relaxed">{aiStatus}</p>
            </div>
            {detail && (
              <div className="col-span-2">
                <p className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold mb-1">Evidência / Detalhe</p>
                <pre className="text-[11px] font-mono text-gray-400 bg-black/30 rounded-lg p-3 overflow-x-auto whitespace-pre-wrap break-words max-h-40">
                  {typeof detail === 'string' ? detail : JSON.stringify(detail, null, 2)}
                </pre>
              </div>
            )}
            {finding.reference && (
              <div>
                <p className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold mb-1">Referência</p>
                <a href={finding.reference} target="_blank" rel="noopener noreferrer"
                   className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 transition-colors">
                  <ExternalLink className="w-3 h-3" /> {finding.reference}
                </a>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Target Card ───────────────────────────────────────────────────────────────

function TargetCard({ target, scanData, isScanning, onScan, onRemove }) {
  const hasData     = !!scanData;
  const findings    = hasData ? (scanData.findings_prioritized || scanData.findings || scanData.vulnerabilities || []) : [];
  const critical    = findings.filter(f => (f.severity || f.risk || '').toUpperCase() === 'CRITICAL').length;
  const high        = findings.filter(f => (f.severity || f.risk || '').toUpperCase() === 'HIGH').length;
  const isActive    = isScanning;

  return (
    <div className={`relative flex flex-col rounded-2xl border overflow-hidden transition-all duration-300
                     ${hasData
                       ? 'bg-gradient-to-b from-[#0d1421]/80 to-[#060b13]/90 border-emerald-500/15 hover:border-emerald-500/30'
                       : 'bg-gradient-to-b from-[#0d1421]/60 to-[#060b13]/80 border-white/[0.06] hover:border-white/[0.12]'
                     }`}
    >
      <div className={`h-[2px] w-full ${hasData ? 'bg-gradient-to-r from-emerald-500/50 to-teal-400/20' : 'bg-gradient-to-r from-white/5 to-transparent'}`} />

      <div className="p-4 flex items-start gap-3">
        {/* Icon */}
        <div className={`w-8 h-8 rounded-xl border flex items-center justify-center shrink-0 mt-0.5
                        ${hasData ? 'bg-emerald-500/10 border-emerald-500/20' : 'bg-white/[0.04] border-white/[0.08]'}`}>
          <Globe className={`w-4 h-4 ${hasData ? 'text-emerald-400' : 'text-gray-500'}`} />
        </div>

        <div className="flex-1 min-w-0">
          <p className="text-xs font-bold text-white truncate">{target}</p>

          {/* Status */}
          <div className="flex items-center gap-2 mt-1.5">
            {isActive ? (
              <span className="flex items-center gap-1.5 text-[10px] text-amber-400 font-semibold">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
                Varrendo...
              </span>
            ) : hasData ? (
              <>
                <span className="flex items-center gap-1.5 text-[10px] text-emerald-400 font-semibold">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                  DAST Completo
                </span>
                {critical > 0 && <span className="text-[10px] text-rose-400 font-bold">{critical} CRIT</span>}
                {high > 0    && <span className="text-[10px] text-red-400 font-bold">{high} HIGH</span>}
              </>
            ) : (
              <span className="flex items-center gap-1.5 text-[10px] text-amber-500 font-semibold">
                <Clock className="w-3 h-3" />
                Pendente de Scan
              </span>
            )}
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center gap-1 shrink-0">
          <button
            onClick={() => onScan(target)}
            disabled={isActive}
            title="Iniciar Pentest DAST"
            className="p-1.5 rounded-lg bg-white/[0.04] border border-white/[0.07] text-gray-500
                       hover:bg-emerald-500/10 hover:text-emerald-400 hover:border-emerald-500/25
                       transition-all disabled:opacity-30 disabled:cursor-not-allowed"
          >
            <Play className="w-3 h-3" />
          </button>
          <button
            onClick={() => onRemove(target)}
            title="Remover alvo"
            className="p-1.5 rounded-lg bg-white/[0.04] border border-white/[0.07] text-gray-500
                       hover:bg-red-500/10 hover:text-red-400 hover:border-red-500/25 transition-all"
          >
            <Trash2 className="w-3 h-3" />
          </button>
        </div>
      </div>
    </div>
  );
}

// ── WS Status Indicator ───────────────────────────────────────────────────────

function WsStatusDot({ connected }) {
  return (
    <div className="flex items-center gap-1.5">
      {connected
        ? <><span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" /><span className="text-[10px] text-emerald-400 font-semibold">Agente Online</span></>
        : <><span className="w-2 h-2 rounded-full bg-gray-600" /><span className="text-[10px] text-gray-500 font-semibold">Agente Offline</span></>
      }
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function DomainsPage() {
  const [targets, setTargets]           = useState([]);         // lista de alvos cadastrados
  const [targetInput, setTargetInput]   = useState('');
  const [scanningTarget, setScanningTarget] = useState(null);   // URL sendo varrida agora
  const [selectedTarget, setSelectedTarget] = useState(null);   // alvo cujos resultados estão na tabela
  const [scanResults, setScanResults]   = useState({});         // { url: scanData }
  const [wsConnected, setWsConnected]   = useState(false);
  const [logs, setLogs]                 = useState([]);
  const [toast, setToast]               = useState(null);
  const [showLogs, setShowLogs]         = useState(false);
  const [severityFilter, setSeverityFilter] = useState('ALL');

  const wsRef       = useRef(null);
  const logsEndRef  = useRef(null);

  const showToast = useCallback((msg) => {
    setToast(msg);
    setTimeout(() => setToast(null), 3500);
  }, []);

  const addLog = useCallback((text, type = 'info') => {
    const ts = new Date().toLocaleTimeString('pt-BR');
    setLogs(prev => [...prev.slice(-300), { text, type, ts, id: Date.now() + Math.random() }]);
  }, []);

  // ── Scroll automático do console ────────────────────────────────────────────
  useEffect(() => {
    if (showLogs) logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs, showLogs]);

  // ── Hidratação do localStorage ──────────────────────────────────────────────
  useEffect(() => {
    // Carrega lista de alvos cadastrados
    const savedTargets = localStorage.getItem('previswit_dast_targets');
    let loadedTargets = [];
    if (savedTargets) {
      try { loadedTargets = JSON.parse(savedTargets); } catch (_) {}
    }

    // Hidrata resultados de cada alvo
    const hydratedResults = {};
    loadedTargets.forEach(url => {
      const cached = localStorage.getItem(storageKey(url));
      if (cached) {
        try { hydratedResults[url] = JSON.parse(cached); } catch (_) {}
      }
    });

    setTargets(loadedTargets);
    setScanResults(hydratedResults);

    // Seleciona automaticamente o primeiro alvo com resultado
    const withData = loadedTargets.find(u => hydratedResults[u]);
    if (withData) setSelectedTarget(withData);
  }, []);

  // ── WebSocket ───────────────────────────────────────────────────────────────
  useEffect(() => {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url   = `${proto}//${window.location.host}/ws/web_dashboard`;

    const connect = () => {
      wsRef.current = new WebSocket(url);

      wsRef.current.onopen = () => {
        setWsConnected(true);
        addLog('Conectado ao servidor PreviSwit via WebSocket.', 'system');
      };

      wsRef.current.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);

          if (msg.action === 'LOG') {
            addLog(msg.message, 'info');

          } else if (msg.action === 'SCAN_RESULT' || msg.status === 'SCAN_RESULT') {
            const data = msg.data || msg;
            const url  = msg.target || scanningTarget;

            if (url) {
              // Grava no localStorage
              const payload = data;
              localStorage.setItem(storageKey(url), JSON.stringify(payload));

              setScanResults(prev => ({ ...prev, [url]: payload }));
              setSelectedTarget(url);
              setScanningTarget(null);

              const findings = payload.findings_prioritized || payload.findings || payload.vulnerabilities || [];
              showToast(`Scan concluído — ${findings.length} finding${findings.length !== 1 ? 's' : ''} detectado${findings.length !== 1 ? 's' : ''}`);
              addLog(`Scan DAST concluído para ${url} — ${findings.length} findings.`, 'success');
            }

          } else if (msg.action === 'SCAN_ERROR' || msg.status === 'SCAN_ERROR') {
            setScanningTarget(null);
            addLog(`Erro no scan: ${msg.error || 'Erro desconhecido'}`, 'error');
            showToast('Erro durante o scan DAST');
          }
        } catch (e) {
          console.error('[DomainsPage] Erro ao processar WS msg:', e);
        }
      };

      wsRef.current.onerror = () => {
        setWsConnected(false);
        addLog('Erro na conexão WebSocket.', 'error');
      };

      wsRef.current.onclose = () => {
        setWsConnected(false);
        addLog('WebSocket desconectado. Tentando reconectar...', 'system');
        setTimeout(connect, 3000);
      };
    };

    connect();

    return () => {
      wsRef.current?.close(1000, 'Component unmounted');
    };
  }, []); // eslint-disable-line

  // ── Adicionar alvo ──────────────────────────────────────────────────────────
  const handleAddTarget = () => {
    const url = normalizeUrl(targetInput);
    if (!url) return;
    if (targets.includes(url)) {
      showToast('Alvo já cadastrado');
      return;
    }
    const updated = [...targets, url];
    setTargets(updated);
    localStorage.setItem('previswit_dast_targets', JSON.stringify(updated));
    setTargetInput('');
    showToast(`Alvo adicionado: ${url}`);
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') handleAddTarget();
  };

  // ── Remover alvo ────────────────────────────────────────────────────────────
  const handleRemoveTarget = (url) => {
    const updated = targets.filter(t => t !== url);
    setTargets(updated);
    localStorage.setItem('previswit_dast_targets', JSON.stringify(updated));
    localStorage.removeItem(storageKey(url));
    setScanResults(prev => { const n = { ...prev }; delete n[url]; return n; });
    if (selectedTarget === url) setSelectedTarget(updated[0] || null);
    showToast('Alvo removido');
  };

  // ── Iniciar scan DAST ───────────────────────────────────────────────────────
  const handleScan = (url) => {
    if (!wsConnected) {
      showToast('Agente offline. Aguarde a reconexão do WebSocket.');
      return;
    }
    if (scanningTarget) {
      showToast('Aguarde o scan atual terminar.');
      return;
    }

    setScanningTarget(url);
    setSelectedTarget(url);
    setSeverityFilter('ALL');
    addLog(`Disparando Pentest DAST para: ${url}`, 'system');

    wsRef.current.send(JSON.stringify({
      action:   'START_SCAN',
      target:   url,
      pipeline: 'dast_api',
    }));

    showToast(`Scan iniciado: ${url}`);
  };

  // ── Iniciar scan do input direto ────────────────────────────────────────────
  const handleDirectScan = () => {
    const url = normalizeUrl(targetInput);
    if (!url) { showToast('Informe um domínio ou URL'); return; }
    // Adiciona se não existe
    if (!targets.includes(url)) {
      const updated = [...targets, url];
      setTargets(updated);
      localStorage.setItem('previswit_dast_targets', JSON.stringify(updated));
    }
    setTargetInput('');
    handleScan(url);
  };

  // ── Computed ─────────────────────────────────────────────────────────────────
  const activeScanData = selectedTarget ? scanResults[selectedTarget] : null;
  const allFindings    = activeScanData
    ? (activeScanData.findings_prioritized || activeScanData.findings || activeScanData.vulnerabilities || [])
    : [];

  const filteredFindings = severityFilter === 'ALL'
    ? allFindings
    : allFindings.filter(f => (f.severity || f.risk || '').toUpperCase() === severityFilter);

  const countBySev = (sev) => allFindings.filter(f => (f.severity || f.risk || '').toUpperCase() === sev).length;

  const SEVERITY_TABS = [
    { key: 'ALL',      label: 'Todos',    count: allFindings.length,  cls: 'text-white' },
    { key: 'CRITICAL', label: 'Critical', count: countBySev('CRITICAL'), cls: 'text-rose-400' },
    { key: 'HIGH',     label: 'High',     count: countBySev('HIGH'),     cls: 'text-red-400' },
    { key: 'MEDIUM',   label: 'Medium',   count: countBySev('MEDIUM'),   cls: 'text-amber-400' },
    { key: 'LOW',      label: 'Low',      count: countBySev('LOW'),      cls: 'text-blue-400' },
  ];

  const logTypeClass = { system: 'text-gray-500', info: 'text-gray-300', error: 'text-red-400', success: 'text-emerald-400' };

  return (
    <section id="view-domains" className="w-full flex flex-col gap-6">

      {/* ── Header ──────────────────────────────────────────────────────── */}
      <div className="flex items-start justify-between gap-4">
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-1.5">
            <NavLink to="/assets" className="text-xs text-gray-600 hover:text-gray-400 flex items-center gap-1 transition-colors">
              <ArrowLeft className="w-3 h-3" />
              Ativos &amp; Produtos
            </NavLink>
            <span className="text-gray-700">/</span>
            <span className="text-xs text-emerald-400 font-medium">Domínios &amp; APIs</span>
          </div>
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2.5">
              <Globe className="w-5 h-5 text-emerald-400" />
              Domínios &amp; APIs
            </h1>
            <p className="text-sm text-gray-500 mt-0.5">
              Superfície de Ataque Externa · DAST · API Security Testing
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <WsStatusDot connected={wsConnected} />
          <button
            onClick={() => setShowLogs(s => !s)}
            className={`p-2 rounded-lg border transition-all ${showLogs ? 'bg-white/10 border-white/20 text-white' : 'border-white/[0.08] text-gray-500 hover:text-white hover:bg-white/5'}`}
          >
            <Terminal className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* ── Add Target + Quick Scan Panel ───────────────────────────────── */}
      <div className="bg-gradient-to-b from-[#0d1421]/80 to-[#060b13]/90 border border-white/[0.06] rounded-2xl overflow-hidden">
        <div className="h-[2px] w-full bg-gradient-to-r from-emerald-500/50 to-teal-400/20" />
        <div className="p-6">
          <div className="flex items-center gap-3 mb-5">
            <div className="w-9 h-9 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
              <Zap className="w-4 h-4 text-emerald-400" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white">Adicionar Alvo / Iniciar Pentest</h2>
              <p className="text-[11px] text-gray-500 mt-0.5">Domínio, URL ou endpoint de API pública</p>
            </div>
          </div>

          <div className="flex gap-3">
            <div className="flex-1 relative">
              <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-600" />
              <input
                type="text"
                value={targetInput}
                onChange={e => setTargetInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="https://meu-dominio.com ou api.banco.com/v1"
                className="w-full bg-[#111827] border border-white/[0.08] rounded-xl pl-10 pr-4 py-2.5
                           text-sm text-white placeholder:text-gray-600 focus:outline-none
                           focus:border-emerald-500/40 focus:ring-1 focus:ring-emerald-500/20 transition-all"
              />
            </div>
            <button
              onClick={handleAddTarget}
              title="Adicionar à lista"
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold border
                         border-white/[0.10] bg-white/[0.05] text-gray-300
                         hover:bg-white/[0.10] hover:text-white hover:border-white/20 transition-all"
            >
              <Plus className="w-4 h-4" />
              Adicionar
            </button>
            <button
              onClick={handleDirectScan}
              disabled={!!scanningTarget}
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold
                         bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-500/20
                         transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {scanningTarget
                ? <><span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Varrendo...</>
                : <><Play className="w-4 h-4" /> Iniciar Pentest DAST / API</>
              }
            </button>
          </div>
        </div>
      </div>

      {/* ── Target Grid ─────────────────────────────────────────────────── */}
      {targets.length > 0 && (
        <div>
          <p className="text-[10px] text-gray-600 uppercase tracking-wider font-semibold mb-3">
            Alvos Cadastrados · {targets.length}
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
            {targets.map(url => (
              <div
                key={url}
                onClick={() => { setSelectedTarget(url); setSeverityFilter('ALL'); }}
                className={`cursor-pointer ring-2 transition-all rounded-2xl ${selectedTarget === url ? 'ring-emerald-500/40' : 'ring-transparent'}`}
              >
                <TargetCard
                  target={url}
                  scanData={scanResults[url]}
                  isScanning={scanningTarget === url}
                  onScan={handleScan}
                  onRemove={handleRemoveTarget}
                />
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── KPI Strip (pós-scan) ────────────────────────────────────────── */}
      {activeScanData && allFindings.length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: 'Total Findings', value: allFindings.length, color: 'text-white', border: 'border-emerald-500/15', icon: <Database className="w-4 h-4 text-emerald-400" /> },
            { label: 'Critical',       value: countBySev('CRITICAL'), color: 'text-rose-400',  border: 'border-rose-500/15',  icon: <AlertTriangle className="w-4 h-4 text-rose-400" /> },
            { label: 'High',           value: countBySev('HIGH'),     color: 'text-red-400',   border: 'border-red-500/15',   icon: <TrendingUp className="w-4 h-4 text-red-400" /> },
            { label: 'Medium / Low',   value: countBySev('MEDIUM') + countBySev('LOW'), color: 'text-amber-400', border: 'border-amber-500/15', icon: <Activity className="w-4 h-4 text-amber-400" /> },
          ].map(kpi => (
            <div key={kpi.label} className={`bg-gradient-to-b from-[#0d1421]/70 to-[#060b13]/60 border ${kpi.border} rounded-2xl p-4 flex items-center gap-3`}>
              <div className="w-9 h-9 rounded-xl bg-white/[0.04] border border-white/[0.06] flex items-center justify-center shrink-0">
                {kpi.icon}
              </div>
              <div>
                <p className="text-[10px] text-gray-600 uppercase tracking-wider font-semibold">{kpi.label}</p>
                <p className={`text-2xl font-bold mt-0.5 leading-none ${kpi.color}`}>{kpi.value}</p>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ── DataGrid de Findings ─────────────────────────────────────────── */}
      {activeScanData && (
        <div className="bg-gradient-to-b from-[#0d1421]/80 to-[#060b13]/90 border border-white/[0.06] rounded-2xl overflow-hidden">
          {/* Toolbar */}
          <div className="px-5 py-4 border-b border-white/[0.05] flex items-center justify-between flex-wrap gap-3">
            <div className="flex items-center gap-2.5">
              <span className="w-1 h-5 rounded-full bg-emerald-500/60" />
              <h3 className="text-sm font-bold text-white">
                Resultados DAST
                {selectedTarget && <span className="ml-2 text-[11px] font-normal text-gray-500 font-mono">{selectedTarget}</span>}
              </h3>
              <span className="text-[10px] text-gray-500 bg-white/[0.04] border border-white/[0.06] px-2 py-0.5 rounded-md">
                {filteredFindings.length} / {allFindings.length}
              </span>
            </div>

            {/* Severity tabs */}
            <div className="flex items-center gap-1">
              {SEVERITY_TABS.filter(t => t.count > 0 || t.key === 'ALL').map(tab => (
                <button
                  key={tab.key}
                  onClick={() => setSeverityFilter(tab.key)}
                  className={`flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11px] font-semibold transition-all
                              ${severityFilter === tab.key
                                ? 'bg-white/10 border border-white/15 text-white'
                                : 'text-gray-600 hover:text-gray-300 hover:bg-white/5 border border-transparent'
                              }`}
                >
                  <span className={tab.cls}>{tab.label}</span>
                  <span className="text-gray-600">({tab.count})</span>
                </button>
              ))}
            </div>
          </div>

          {/* Column headers */}
          <div className="grid grid-cols-12 gap-3 px-4 py-2.5 text-[10px] text-gray-500 uppercase tracking-wider font-semibold border-b border-white/[0.04] bg-white/[0.02]">
            <div className="col-span-1">#</div>
            <div className="col-span-4">Endpoint / URL</div>
            <div className="col-span-3">Vulnerabilidade Encontrada</div>
            <div className="col-span-2">Severidade</div>
            <div className="col-span-2">Validação da IA</div>
          </div>

          {/* Rows */}
          <div className="max-h-[520px] overflow-y-auto">
            {filteredFindings.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 gap-3">
                <div className="w-12 h-12 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
                  <Shield className="w-5 h-5 text-emerald-400" />
                </div>
                <p className="text-sm font-semibold text-emerald-400">
                  {severityFilter === 'ALL' ? 'Nenhuma vulnerabilidade detectada' : `Sem findings de severidade ${severityFilter}`}
                </p>
                <p className="text-xs text-gray-600">
                  {severityFilter === 'ALL' ? 'O alvo está em conformidade para os vetores analisados.' : 'Tente outro filtro.'}
                </p>
              </div>
            ) : (
              filteredFindings.map((f, i) => (
                <FindingRow key={`${f.cve_id || f.name || i}-${i}`} finding={f} index={i} />
              ))
            )}
          </div>
        </div>
      )}

      {/* ── Empty state (sem alvos) ──────────────────────────────────────── */}
      {targets.length === 0 && (
        <div className="flex flex-col items-center justify-center p-16 border border-dashed border-white/[0.06] rounded-2xl bg-gradient-to-b from-[#0d1421]/40 to-transparent">
          <div className="relative mb-6">
            <div className="w-16 h-16 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
              <Globe className="w-7 h-7 text-emerald-400/60" />
            </div>
            <div className="absolute -bottom-1 -right-1 w-5 h-5 rounded-full bg-blue-500/20 border border-blue-500/30 flex items-center justify-center">
              <Play className="w-2.5 h-2.5 text-blue-400" />
            </div>
          </div>
          <p className="text-sm font-semibold text-gray-300 text-center">Nenhum alvo cadastrado</p>
          <p className="text-xs text-gray-600 text-center mt-2 max-w-sm leading-relaxed">
            Adicione um domínio ou endpoint de API acima (ex: <span className="font-mono text-emerald-500">https://meu-site.com</span>)
            e inicie o Pentest DAST para mapear a superfície de ataque.
          </p>
        </div>
      )}

      {/* ── Console de Logs WS ───────────────────────────────────────────── */}
      {showLogs && (
        <div className="bg-[#070c13] border border-white/[0.06] rounded-2xl overflow-hidden">
          <div className="px-4 py-3 border-b border-white/[0.05] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-emerald-400" />
              <span className="text-xs font-bold text-white">Console WebSocket</span>
            </div>
            <button onClick={() => setLogs([])} className="text-[10px] text-gray-600 hover:text-gray-300 transition-colors">
              Limpar
            </button>
          </div>
          <div className="p-4 h-48 overflow-y-auto font-mono text-[11px] space-y-1">
            {logs.length === 0
              ? <p className="text-gray-600 italic">Aguardando eventos...</p>
              : logs.map(l => (
                <div key={l.id} className="flex gap-2">
                  <span className="text-gray-600 shrink-0">{l.ts}</span>
                  <span className={logTypeClass[l.type] || 'text-gray-400'}>{l.text}</span>
                </div>
              ))
            }
            <div ref={logsEndRef} />
          </div>
        </div>
      )}

      {/* ── Scanning progress overlay ─────────────────────────────────────── */}
      {scanningTarget && !activeScanData && (
        <div className="flex flex-col items-center justify-center py-16 gap-4">
          <div className="relative">
            <div className="w-10 h-10 border-2 border-emerald-500/30 rounded-full" />
            <div className="w-10 h-10 border-2 border-emerald-500 border-t-transparent rounded-full animate-spin absolute inset-0" />
          </div>
          <div className="text-center">
            <p className="text-sm font-semibold text-white">Executando Pentest DAST</p>
            <p className="text-xs text-gray-500 mt-1">
              Varrendo <span className="font-mono text-emerald-400">{scanningTarget}</span>...
            </p>
          </div>
        </div>
      )}

      {/* ── Toast ─────────────────────────────────────────────────────────── */}
      {toast && (
        <div className="fixed bottom-6 right-6 z-[500] flex items-center gap-2 px-4 py-3 rounded-lg
                        shadow-2xl border border-emerald-500/30 bg-[#0d1421]/95 backdrop-blur-md
                        text-xs font-medium text-emerald-200">
          <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
          {toast}
        </div>
      )}

    </section>
  );
}
