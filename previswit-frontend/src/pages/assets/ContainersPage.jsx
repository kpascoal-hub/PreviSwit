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
 * PreviSwit AI-ASPM — Container Security (Trivy Image Scanner)
 * =============================================================
 * Análise de vulnerabilidades (CVEs) em imagens Docker via Trivy.
 *
 * Estrutura:
 *   - Header executivo com breadcrumb de navegação
 *   - Painel de scan: input de nome de imagem + botão de scan
 *   - KPI Strip: Total, Critical, High, Medium, Low/Unknown
 *   - DataGrid: Tabela de CVEs com CVE ID, Pacote, Severidade, Versão Atual, Fix
 *   - Hidratação via localStorage (previswit_container_<imageName>)
 *   - Polling assíncrono idêntico ao CloudPage e RepositoriesPage
 *
 * Regra: ZERO manipulação direta do DOM. Estado via useState/useEffect.
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { NavLink } from 'react-router-dom';
import {
  ArrowLeft, Box, Shield, AlertTriangle, RefreshCw,
  Search, CheckCircle, Activity, Database,
  TrendingUp, ChevronRight, ExternalLink,
  Package, Layers, Zap, Info, Clock, Trash2,
} from 'lucide-react';

const API = '/api/v1';

// ── Helpers ───────────────────────────────────────────────────────────────────

function severityColors(sev) {
  const s = (sev || '').toUpperCase();
  if (s === 'CRITICAL') return { bg: 'bg-rose-500/10', text: 'text-rose-400', border: 'border-rose-500/25', dot: 'bg-rose-500',  badge: 'bg-rose-500/15 text-rose-300' };
  if (s === 'HIGH')     return { bg: 'bg-red-500/10',  text: 'text-red-400',  border: 'border-red-500/25',  dot: 'bg-red-500',   badge: 'bg-red-500/15 text-red-300' };
  if (s === 'MEDIUM')   return { bg: 'bg-amber-500/10',text: 'text-amber-400',border: 'border-amber-500/25',dot: 'bg-amber-500', badge: 'bg-amber-500/15 text-amber-300' };
  if (s === 'LOW')      return { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/25', dot: 'bg-blue-500',  badge: 'bg-blue-500/15 text-blue-300' };
  return                         { bg: 'bg-gray-500/10',text: 'text-gray-400', border: 'border-gray-500/25', dot: 'bg-gray-500',  badge: 'bg-gray-500/15 text-gray-400' };
}

function cvssColor(score) {
  if (!score) return 'text-gray-600';
  if (score >= 9.0) return 'text-rose-400';
  if (score >= 7.0) return 'text-red-400';
  if (score >= 4.0) return 'text-amber-400';
  return 'text-blue-400';
}

// ── CVE Row ───────────────────────────────────────────────────────────────────

function CveRow({ vuln, index }) {
  const [expanded, setExpanded] = useState(false);
  const sev = severityColors(vuln.severity);
  const hasFixVersion = vuln.fixed_version && vuln.fixed_version !== 'Sem correção disponível';

  return (
    <div className="group border-b border-white/[0.04] last:border-0">
      {/* Main row */}
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

        {/* CVE ID */}
        <div className="col-span-2 min-w-0">
          <span className="text-xs font-mono font-bold text-cyan-400 hover:text-cyan-300 transition-colors">
            {vuln.cve_id}
          </span>
          {vuln.cvss_score != null && (
            <div className={`text-[10px] font-bold mt-0.5 ${cvssColor(vuln.cvss_score)}`}>
              CVSS {vuln.cvss_score}
            </div>
          )}
        </div>

        {/* Package */}
        <div className="col-span-2 min-w-0 flex items-center gap-2">
          <div className="w-6 h-6 rounded-lg bg-white/[0.04] border border-white/[0.06] flex items-center justify-center shrink-0">
            <Package className="w-3 h-3 text-gray-500" />
          </div>
          <span className="text-xs font-medium text-gray-300 truncate">{vuln.package}</span>
        </div>

        {/* Severity */}
        <div className="col-span-2">
          <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-[10px] font-bold tracking-wide ${sev.bg} ${sev.text} ${sev.border}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${sev.dot}`} />
            {vuln.severity}
          </span>
        </div>

        {/* Installed version */}
        <div className="col-span-2 min-w-0">
          <span className="text-[11px] font-mono text-gray-400 truncate block">
            {vuln.installed_version}
          </span>
          <span className="text-[9px] text-gray-600 uppercase tracking-wide">atual</span>
        </div>

        {/* Fixed version */}
        <div className="col-span-2 min-w-0">
          {hasFixVersion ? (
            <>
              <span className="text-[11px] font-mono text-emerald-400 truncate block">
                {vuln.fixed_version}
              </span>
              <span className="text-[9px] text-gray-600 uppercase tracking-wide">fix disponível</span>
            </>
          ) : (
            <span className="text-[11px] text-gray-600 italic">Sem fix</span>
          )}
        </div>

        {/* Expand arrow */}
        <div className="col-span-1 flex justify-end">
          <ChevronRight
            className={`w-3.5 h-3.5 text-gray-600 transition-transform duration-200 ${expanded ? 'rotate-90' : ''}`}
          />
        </div>
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div className="px-4 py-4 bg-[#060b13]/70 border-b border-white/[0.04]">
          <div className="grid grid-cols-2 gap-5">
            {/* Title / description */}
            <div className="col-span-2">
              <p className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold mb-1">Descrição</p>
              <p className="text-xs text-gray-400 leading-relaxed line-clamp-3">
                {vuln.title || vuln.description || 'Sem descrição disponível.'}
              </p>
            </div>

            {/* Target */}
            {vuln.target && (
              <div>
                <p className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold mb-1">Alvo / Camada</p>
                <p className="text-xs font-mono text-gray-400">{vuln.target}</p>
              </div>
            )}

            {/* References */}
            {vuln.references?.length > 0 && (
              <div>
                <p className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold mb-1">Referências</p>
                <div className="flex flex-col gap-1">
                  {vuln.references.map((ref, i) => (
                    <a key={i} href={ref} target="_blank" rel="noopener noreferrer"
                       className="text-[11px] text-blue-400 hover:text-blue-300 flex items-center gap-1 transition-colors truncate">
                      <ExternalLink className="w-3 h-3 shrink-0" />
                      <span className="truncate">{ref}</span>
                    </a>
                  ))}
                </div>
              </div>
            )}

            {/* Primary URL */}
            {vuln.primary_url && (
              <div>
                <p className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold mb-1">Banco de Vulnerabilidades</p>
                <a href={vuln.primary_url} target="_blank" rel="noopener noreferrer"
                   className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors">
                  <ExternalLink className="w-3 h-3" />
                  {vuln.cve_id} — NVD / OSV
                </a>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Suggested Image Chip ──────────────────────────────────────────────────────

function SuggestedChip({ name, onClick }) {
  return (
    <button
      onClick={() => onClick(name)}
      className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-white/[0.07]
                 bg-white/[0.03] text-[11px] text-gray-500 hover:text-cyan-300
                 hover:bg-cyan-500/10 hover:border-cyan-500/25 transition-all duration-150 font-mono"
    >
      <Box className="w-3 h-3" />
      {name}
    </button>
  );
}

// ── KPI Card ──────────────────────────────────────────────────────────────────

function KpiCard({ label, value, icon, accentClass, borderClass }) {
  return (
    <div className={`bg-gradient-to-b from-[#0d1421]/70 to-[#060b13]/60 border ${borderClass} rounded-2xl p-4 flex items-center gap-3`}>
      <div className="w-9 h-9 rounded-xl bg-white/[0.04] border border-white/[0.06] flex items-center justify-center shrink-0">
        {icon}
      </div>
      <div>
        <p className="text-[10px] text-gray-600 uppercase tracking-wider font-semibold">{label}</p>
        <p className={`text-2xl font-bold mt-0.5 leading-none ${accentClass}`}>{value}</p>
      </div>
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

const SUGGESTIONS = ['nginx:latest', 'ubuntu:22.04', 'node:18-alpine', 'python:3.12-slim', 'redis:7-alpine'];

export default function ContainersPage() {
  const [imageInput, setImageInput]       = useState('');
  const [scanStatus, setScanStatus]       = useState(null);
  const [scanId, setScanId]               = useState(null);
  const [scanData, setScanData]           = useState(null);
  const [scanError, setScanError]         = useState(null);
  const [lastImage, setLastImage]         = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [toast, setToast]                 = useState(null);
  const pollingRef                        = useRef(null);

  const showToast = (msg) => {
    setToast(msg);
    setTimeout(() => setToast(null), 3500);
  };

  // ── Hidratação do último scan via localStorage ──────────────────────────────
  useEffect(() => {
    const lastKey = localStorage.getItem('previswit_container_last_key');
    if (lastKey) {
      const cached = localStorage.getItem('previswit_container_' + lastKey);
      if (cached) {
        try {
          const parsed = JSON.parse(cached);
          setScanData(parsed);
          setScanStatus('CONCLUÍDO');
          setLastImage(lastKey);
          setImageInput(lastKey);
        } catch (_) {}
      }
    }
  }, []);

  // ── Limpar polling ao desmontar ─────────────────────────────────────────────
  useEffect(() => {
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, []);

  // ── Polling de Status ───────────────────────────────────────────────────────
  const startPolling = useCallback((id, imageName) => {
    if (pollingRef.current) clearInterval(pollingRef.current);

    pollingRef.current = setInterval(async () => {
      try {
        const res = await fetch(`${API}/containers/scan-status/${id}`);
        if (!res.ok) return;
        const data = await res.json();

        setScanStatus(data.status);

        if (data.status === 'CONCLUÍDO') {
          clearInterval(pollingRef.current);
          const result = data.data;
          setScanData(result);
          setLastImage(imageName);

          // Grava no localStorage com a chave da imagem
          localStorage.setItem('previswit_container_' + imageName, JSON.stringify(result));
          localStorage.setItem('previswit_container_last_key', imageName);

          const total = result?.stats?.total ?? 0;
          showToast(`Scan concluído — ${total} CVE${total !== 1 ? 's' : ''} encontrado${total !== 1 ? 's' : ''}`);

        } else if (data.status === 'ERROR') {
          clearInterval(pollingRef.current);
          setScanError(data.error || 'Erro desconhecido no scan.');
          showToast('Erro durante o scan');
        }
      } catch (e) {
        console.error('[ContainersPage] Polling error:', e);
      }
    }, 3000);
  }, []);

  // ── Iniciar Scan ────────────────────────────────────────────────────────────
  const handleScan = async () => {
    const image = imageInput.trim();
    if (!image) {
      showToast('Informe o nome da imagem Docker');
      return;
    }

    // Reseta estado
    setScanStatus('PENDING');
    setScanData(null);
    setScanError(null);
    setSeverityFilter('ALL');

    try {
      const res = await fetch(`${API}/containers/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ image_name: image }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }

      const data = await res.json();
      setScanId(data.scan_id);
      showToast(`Scan iniciado para ${image}`);
      startPolling(data.scan_id, image);

    } catch (e) {
      setScanStatus('ERROR');
      setScanError(e.message || 'Falha de conexão com o backend');
      showToast('Falha ao iniciar scan');
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') handleScan();
  };

  const handleClearScan = () => {
    if (lastImage) {
      localStorage.removeItem('previswit_container_' + lastImage);
    }
    localStorage.removeItem('previswit_container_last_key');
    setScanData(null);
    setScanStatus(null);
    setScanError(null);
    setScanId(null);
    setLastImage('');
    setImageInput('');
    showToast('Registros de vulnerabilidades removidos');
  };

  // ── Computed ─────────────────────────────────────────────────────────────────
  const isScanning   = scanStatus === 'PENDING' || scanStatus === 'RUNNING';
  const isConcluded  = scanStatus === 'CONCLUÍDO';
  const allVulns     = scanData?.vulnerabilities || [];
  const stats        = scanData?.stats || {};

  const filteredVulns = severityFilter === 'ALL'
    ? allVulns
    : allVulns.filter(v => (v.severity || '').toUpperCase() === severityFilter);

  const SEVERITY_TABS = [
    { key: 'ALL',      label: 'Todos',    count: allVulns.length,                                         cls: 'text-white' },
    { key: 'CRITICAL', label: 'Critical', count: stats.critical ?? 0,                                     cls: 'text-rose-400' },
    { key: 'HIGH',     label: 'High',     count: stats.high     ?? 0,                                     cls: 'text-red-400' },
    { key: 'MEDIUM',   label: 'Medium',   count: stats.medium   ?? 0,                                     cls: 'text-amber-400' },
    { key: 'LOW',      label: 'Low',      count: stats.low      ?? 0,                                     cls: 'text-blue-400' },
    { key: 'UNKNOWN',  label: 'Unknown',  count: stats.unknown  ?? 0,                                     cls: 'text-gray-400' },
  ];

  return (
    <section id="view-containers" className="w-full flex flex-col gap-6">

      {/* ── Header ──────────────────────────────────────────────────────── */}
      <div className="flex items-start justify-between gap-4">
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-1.5">
            <NavLink to="/assets" className="text-xs text-gray-600 hover:text-gray-400 flex items-center gap-1 transition-colors">
              <ArrowLeft className="w-3 h-3" />
              Ativos &amp; Produtos
            </NavLink>
            <span className="text-gray-700">/</span>
            <span className="text-xs text-cyan-400 font-medium">Contêineres</span>
          </div>
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2.5">
              <Box className="w-5 h-5 text-cyan-400" />
              Segurança de Contêineres
            </h1>
            <p className="text-sm text-gray-500 mt-0.5">
              Análise de CVEs em Imagens Docker · Motor: Trivy
            </p>
          </div>
        </div>

        {isConcluded && (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-white/[0.04] border border-white/[0.08] shrink-0">
            <Clock className="w-3.5 h-3.5 text-gray-500" />
            <span className="text-[11px] text-gray-400 font-mono truncate max-w-[200px]">{lastImage}</span>
          </div>
        )}
      </div>

      {/* ── Scan Panel ──────────────────────────────────────────────────── */}
      <div className="bg-gradient-to-b from-[#0d1421]/80 to-[#060b13]/90 border border-white/[0.06] rounded-2xl overflow-hidden">
        <div className="h-[2px] w-full bg-gradient-to-r from-cyan-500/50 to-blue-500/30" />
        <div className="p-6">
          <div className="flex items-center gap-3 mb-5">
            <div className="w-9 h-9 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
              <Box className="w-4 h-4 text-cyan-400" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white">Scan de Imagem Docker</h2>
              <p className="text-[11px] text-gray-500 mt-0.5">
                Insira o nome da imagem para varredura de CVEs via Trivy
              </p>
            </div>
          </div>

          {/* Input + Button */}
          <div className="flex gap-3 mb-4">
            <div className="flex-1 relative">
              <Box className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-600" />
              <input
                type="text"
                value={imageInput}
                onChange={e => setImageInput(e.target.value)}
                onKeyDown={handleKeyDown}
                disabled={isScanning}
                placeholder="nginx:latest, ubuntu:22.04, node:18-alpine..."
                className="w-full bg-[#111827] border border-white/[0.08] rounded-xl pl-10 pr-4 py-2.5 text-sm text-white
                           placeholder:text-gray-600 focus:outline-none focus:border-cyan-500/40
                           focus:ring-1 focus:ring-cyan-500/20 transition-all disabled:opacity-50"
              />
            </div>
            <button
              onClick={handleScan}
              disabled={isScanning || !imageInput.trim()}
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold
                         bg-cyan-600 hover:bg-cyan-500 text-white shadow-lg shadow-cyan-500/20
                         transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isScanning
                ? <><span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Analisando...</>
                : <><Search className="w-4 h-4" /> Iniciar Scan</>
              }
            </button>
          </div>

          {/* Suggested images */}
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[10px] text-gray-600 uppercase tracking-wider font-semibold shrink-0">Sugestões:</span>
            {SUGGESTIONS.map(img => (
              <SuggestedChip key={img} name={img} onClick={name => setImageInput(name)} />
            ))}
          </div>

          {/* Scan Error */}
          {scanStatus === 'ERROR' && scanError && (
            <div className="mt-4 flex items-center gap-3 px-4 py-3 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span className="text-xs">{scanError}</span>
            </div>
          )}
        </div>
      </div>

      {/* ── KPI Strip ───────────────────────────────────────────────────── */}
      {isConcluded && (
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          <KpiCard label="Total CVEs"   value={stats.total    ?? 0} accentClass="text-white"      borderClass="border-cyan-500/15"   icon={<Database     className="w-4 h-4 text-cyan-400"   />} />
          <KpiCard label="Critical"     value={stats.critical ?? 0} accentClass="text-rose-400"   borderClass="border-rose-500/15"   icon={<AlertTriangle className="w-4 h-4 text-rose-400"  />} />
          <KpiCard label="High"         value={stats.high     ?? 0} accentClass="text-red-400"    borderClass="border-red-500/15"    icon={<TrendingUp    className="w-4 h-4 text-red-400"    />} />
          <KpiCard label="Medium"       value={stats.medium   ?? 0} accentClass="text-amber-400"  borderClass="border-amber-500/15"  icon={<Activity      className="w-4 h-4 text-amber-400"  />} />
          <KpiCard label="Low / Unknown"value={(stats.low ?? 0) + (stats.unknown ?? 0)} accentClass="text-blue-400" borderClass="border-blue-500/15" icon={<Shield className="w-4 h-4 text-blue-400" />} />
        </div>
      )}

      {/* ── CVE DataGrid ────────────────────────────────────────────────── */}
      {isConcluded && (
        <div className="bg-gradient-to-b from-[#0d1421]/80 to-[#060b13]/90 border border-white/[0.06] rounded-2xl overflow-hidden">
          {/* Table toolbar */}
          <div className="px-5 py-4 border-b border-white/[0.05] flex items-center justify-between flex-wrap gap-3">
            <div className="flex items-center gap-2.5">
              <span className="w-1 h-5 rounded-full bg-cyan-500/60" />
              <h3 className="text-sm font-bold text-white">Vulnerabilidades (CVEs)</h3>
              <span className="text-[10px] text-gray-500 bg-white/[0.04] border border-white/[0.06] px-2 py-0.5 rounded-md">
                {filteredVulns.length} / {allVulns.length}
              </span>
              <button
                onClick={handleClearScan}
                title="Limpar resultados"
                className="p-1.5 rounded-lg text-gray-600 hover:text-red-400 hover:bg-red-500/10 border border-transparent hover:border-red-500/20 transition-all duration-150"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Severity filter tabs */}
            <div className="flex items-center gap-1">
              {SEVERITY_TABS.filter(t => t.count > 0 || t.key === 'ALL').map(tab => (
                <button
                  key={tab.key}
                  onClick={() => setSeverityFilter(tab.key)}
                  className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px] font-semibold transition-all duration-150
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
            <div className="col-span-2">CVE</div>
            <div className="col-span-2">Pacote Afetado</div>
            <div className="col-span-2">Severidade</div>
            <div className="col-span-2">Versão Atual</div>
            <div className="col-span-2">Versão Corrigida (Fix)</div>
            <div className="col-span-1" />
          </div>

          {/* Rows */}
          <div className="max-h-[560px] overflow-y-auto">
            {filteredVulns.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 gap-3">
                <div className="w-12 h-12 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
                  <Shield className="w-5 h-5 text-emerald-400" />
                </div>
                <p className="text-sm font-semibold text-emerald-400">
                  {severityFilter === 'ALL' ? 'Nenhuma vulnerabilidade detectada' : `Sem CVEs de severidade ${severityFilter}`}
                </p>
                <p className="text-xs text-gray-600">
                  {severityFilter === 'ALL' ? 'A imagem está em conformidade.' : 'Tente outro filtro de severidade.'}
                </p>
              </div>
            ) : (
              filteredVulns.map((vuln, i) => (
                <CveRow key={`${vuln.cve_id}-${vuln.package}-${i}`} vuln={vuln} index={i} />
              ))
            )}
          </div>
        </div>
      )}

      {/* ── Empty state (pré-scan) ──────────────────────────────────────── */}
      {!isConcluded && !isScanning && !scanError && (
        <div className="flex flex-col items-center justify-center p-16 border border-dashed border-white/[0.06] rounded-2xl bg-gradient-to-b from-[#0d1421]/40 to-transparent">
          <div className="relative mb-6">
            <div className="w-16 h-16 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
              <Box className="w-7 h-7 text-cyan-400/60" />
            </div>
            <div className="absolute -bottom-1 -right-1 w-5 h-5 rounded-full bg-blue-500/20 border border-blue-500/30 flex items-center justify-center">
              <Search className="w-2.5 h-2.5 text-blue-400" />
            </div>
          </div>
          <p className="text-sm font-semibold text-gray-300 text-center">Nenhum scan realizado</p>
          <p className="text-xs text-gray-600 text-center mt-2 max-w-sm leading-relaxed">
            Insira o nome de uma imagem Docker acima (ex: <span className="font-mono text-cyan-500">nginx:latest</span>)
            e clique em <strong className="text-white">Iniciar Scan</strong> para detectar CVEs.
          </p>
        </div>
      )}

      {/* ── Scanning progress ────────────────────────────────────────────── */}
      {isScanning && (
        <div className="flex flex-col items-center justify-center py-20 gap-4">
          <div className="relative">
            <div className="w-10 h-10 border-2 border-cyan-500/30 rounded-full" />
            <div className="w-10 h-10 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin absolute inset-0" />
          </div>
          <div className="text-center">
            <p className="text-sm font-semibold text-white">Trivy Analisando Imagem</p>
            <p className="text-xs text-gray-500 mt-1">
              Fazendo pull e varrendo <span className="font-mono text-cyan-400">{imageInput}</span>...
            </p>
          </div>
        </div>
      )}

      {/* ── Toast ────────────────────────────────────────────────────────── */}
      {toast && (
        <div className="fixed bottom-6 right-6 z-[500] flex items-center gap-2 px-4 py-3 rounded-lg
                        shadow-2xl border border-cyan-500/30 bg-[#0d1421]/95 backdrop-blur-md
                        text-xs font-medium text-cyan-200 animate-in slide-in-from-bottom-2">
          <CheckCircle className="w-4 h-4 text-cyan-400 shrink-0" />
          {toast}
        </div>
      )}

    </section>
  );
}
