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
 * PreviSwit AI-ASPM — Central de Relatórios e Conformidade
 *
 * Arquitetura:
 *  - fetchReportsList()         → GET  /api/v1/reports  — carrega e renderiza a tabela
 *  - receiveNewReportEvent()    → POST /api/v1/reports  — salva e atualiza a tabela sem reload
 *  - window.previswit.reports   → API pública para outras abas chamarem receiveNewReportEvent()
 */
import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  FileText, ShieldAlert, ShieldCheck, AlertTriangle,
  Download, RefreshCw, PlusCircle, ChevronDown,
  Filter, Search, X, Clock, Target, Tag, TrendingUp, Trash2,
} from 'lucide-react';

const API = '/api/v1';

// ─── Utilitários ─────────────────────────────────────────────────────────────

const RISK_CONFIG = {
  CRITICAL: { label: 'Crítico',  bg: 'bg-red-500/10',    border: 'border-red-500/30',    text: 'text-red-400',    dot: 'bg-red-500'    },
  HIGH:     { label: 'Alto',     bg: 'bg-orange-500/10', border: 'border-orange-500/30', text: 'text-orange-400', dot: 'bg-orange-500' },
  MEDIUM:   { label: 'Médio',    bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', text: 'text-yellow-400', dot: 'bg-yellow-500' },
  LOW:      { label: 'Baixo',    bg: 'bg-sky-500/10',    border: 'border-sky-500/30',    text: 'text-sky-400',    dot: 'bg-sky-500'    },
  CLEAN:    { label: 'Seguro',   bg: 'bg-emerald-500/10',border: 'border-emerald-500/30',text: 'text-emerald-400',dot: 'bg-emerald-500'},
  UNKNOWN:  { label: '—',        bg: 'bg-gray-800',       border: 'border-gray-700',      text: 'text-gray-400',   dot: 'bg-gray-600'   },
};

function RiskBadge({ risk }) {
  const cfg = RISK_CONFIG[risk?.toUpperCase()] ?? RISK_CONFIG.UNKNOWN;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-bold tracking-wide border ${cfg.bg} ${cfg.border} ${cfg.text}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
      {cfg.label}
    </span>
  );
}

function formatDate(iso) {
  if (!iso) return '—';
  try {
    return new Intl.DateTimeFormat('pt-BR', {
      day: '2-digit', month: '2-digit', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    }).format(new Date(iso));
  } catch {
    return iso;
  }
}



// ─── Componente Principal ─────────────────────────────────────────────────────

export default function ReportsPage() {
  const [reports, setReports]       = useState([]);
  const [loading, setLoading]       = useState(true);
  const [error, setError]           = useState(null);
  const [search, setSearch]         = useState('');
  const [riskFilter, setRiskFilter] = useState('ALL');
  const [toast, setToast]           = useState(null);       // { type, msg }
  const [generating, setGenerating] = useState(false);
  const toastTimer = useRef(null);

  // ─── Toast helper ─────────────────────────────────────────────────────────
  const showToast = useCallback((type, msg) => {
    clearTimeout(toastTimer.current);
    setToast({ type, msg });
    toastTimer.current = setTimeout(() => setToast(null), 4000);
  }, []);

  // ─── Tarefa 2: fetchReportsList ────────────────────────────────────────────
  const fetchReportsList = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res  = await fetch(`${API}/reports/`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setReports(data.reports ?? []);
    } catch (err) {
      setError(`Falha ao carregar relatórios: ${err.message}`);
    } finally {
      setLoading(false);
    }
  }, []);

  // ─── Tarefa 2: receiveNewReportEvent ──────────────────────────────────────
  //   API pública: window.previswit.reports.receive(reportData)
  //   Outras abas (ex: RiskGraphCanvas após scan SAST) chamam esta função.
  const receiveNewReportEvent = useCallback(async (reportData) => {
    // Se o laudo já foi persistido no backend (possui ID e data de conclusão), apenas atualiza o estado
    if (reportData && reportData.id && reportData.completed_at) {
      setReports(prev => {
        const filtered = prev.filter(r => r.id !== reportData.id);
        return [reportData, ...filtered];
      });
      showToast('success', `Novo laudo registrado: ${reportData.title}`);
      return;
    }

    try {
      const res = await fetch(`${API}/reports/`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(reportData),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const saved = await res.json();
      // Atualiza a tabela imediatamente, sem reload
      setReports(prev => {
        const filtered = prev.filter(r => r.id !== saved.report.id);
        return [saved.report, ...filtered];
      });
      showToast('success', `Novo laudo registrado: ${saved.report.title}`);
    } catch (err) {
      showToast('error', `Erro ao salvar relatório: ${err.message}`);
    }
  }, [showToast]);

  const handleDownloadPDF = async (reportId) => {
    try {
      const res = await fetch(`${API}/reports/${reportId}/pdf`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `laudo_${reportId.slice(0, 8)}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      showToast('error', `Falha ao baixar PDF: ${err.message}`);
    }
  };

  const handleDownloadJSON = async (reportId) => {
    try {
      const res = await fetch(`${API}/reports/${reportId}/json`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `laudo_${reportId.slice(0, 8)}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      showToast('error', `Falha ao baixar JSON: ${err.message}`);
    }
  };

  // Expõe a API pública para outras abas via window
  useEffect(() => {
    window.previswit = window.previswit ?? {};
    window.previswit.reports = { receive: receiveNewReportEvent };
    return () => { delete window.previswit?.reports; };
  }, [receiveNewReportEvent]);

  useEffect(() => { fetchReportsList(); }, [fetchReportsList]);

  // ─── "Gerar Novo Relatório Sob Demanda" ───────────────────────────────────
  const handleGenerateNew = async () => {
    setGenerating(true);
    try {
      const res = await fetch(`${API}/reports/generate`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({
          type:  'executive',
          title: `Relatório Executivo — ${new Date().toLocaleDateString('pt-BR')}`,
        }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      showToast('success', 'Solicitação de relatório enviada. A tabela será atualizada em instantes.');
      setTimeout(() => fetchReportsList(), 1500);
    } catch (err) {
      showToast('error', `Falha ao solicitar relatório: ${err.message}`);
    } finally {
      setGenerating(false);
    }
  };

  // ─── Excluir laudo ─────────────────────────────────────────────────────────
  const handleDelete = useCallback(async (reportId, reportTitle) => {
    try {
      const res = await fetch(`${API}/reports/${reportId}`, { method: 'DELETE' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setReports(prev => prev.filter(r => r.id !== reportId));
      showToast('success', `Laudo excluído: ${reportTitle}`);
    } catch (err) {
      showToast('error', `Falha ao excluir laudo: ${err.message}`);
    }
  }, [showToast]);

  // ─── Filtragem ────────────────────────────────────────────────────────────
  const visibleReports = reports.filter(r => {
    const matchSearch =
      !search ||
      r.title?.toLowerCase().includes(search.toLowerCase()) ||
      r.target_label?.toLowerCase().includes(search.toLowerCase()) ||
      r.type?.toLowerCase().includes(search.toLowerCase());
    const matchRisk = riskFilter === 'ALL' || r.risk?.toUpperCase() === riskFilter;
    return matchSearch && matchRisk;
  });

  // ─── Estatísticas rápidas ─────────────────────────────────────────────────
  const stats = {
    total:    reports.length,
    critical: reports.filter(r => r.risk?.toUpperCase() === 'CRITICAL').length,
    high:     reports.filter(r => r.risk?.toUpperCase() === 'HIGH').length,
    clean:    reports.filter(r => ['LOW','CLEAN'].includes(r.risk?.toUpperCase())).length,
  };

  // ─── Render ───────────────────────────────────────────────────────────────
  return (
    <div id="view-reports" className="flex flex-col gap-6 min-h-full">

      {/* Toast */}
      {toast && (
        <div className={`fixed top-6 right-6 z-[500] flex items-center gap-3 px-5 py-3.5 rounded-xl shadow-2xl border text-sm font-medium transition-all animate-in slide-in-from-top-2
          ${toast.type === 'success'
            ? 'bg-emerald-950/90 border-emerald-500/40 text-emerald-200'
            : 'bg-red-950/90 border-red-500/40 text-red-200'}`}>
          {toast.type === 'success'
            ? <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
            : <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />}
          <span>{toast.msg}</span>
          <button onClick={() => setToast(null)} className="ml-2 text-current opacity-60 hover:opacity-100">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* ── Cabeçalho da Seção ─────────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">
            Central de Relatórios e Conformidade
          </h1>
          <p className="text-gray-400 text-sm mt-1 max-w-lg">
            Laudos técnicos e executivos gerados por análises SAST, varreduras de segredos e
            auditorias de conformidade regulatória (ISO 27001, NIST CSF, LGPD).
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={fetchReportsList}
            disabled={loading}
            title="Atualizar lista"
            className="p-2.5 rounded-lg border border-white/10 text-gray-400 hover:text-white hover:bg-white/5 transition-all disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
          <button
            onClick={handleGenerateNew}
            disabled={generating}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-60 text-white text-sm font-semibold transition-all shadow-lg shadow-indigo-500/20"
          >
            <PlusCircle className="w-4 h-4" />
            {generating ? 'Solicitando...' : 'Gerar Novo Relatório Sob Demanda'}
          </button>
        </div>
      </div>

      {/* ── KPI Cards ──────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Total de Laudos', value: stats.total,    icon: FileText,    color: 'text-gray-300',    border: 'border-white/5' },
          { label: 'Risco Crítico',   value: stats.critical, icon: ShieldAlert, color: 'text-red-400',     border: 'border-red-500/20' },
          { label: 'Risco Alto',      value: stats.high,     icon: AlertTriangle,color:'text-orange-400',  border: 'border-orange-500/20' },
          { label: 'Aprovados',       value: stats.clean,    icon: ShieldCheck, color: 'text-emerald-400', border: 'border-emerald-500/20' },
        ].map(({ label, value, icon: Icon, color, border }) => (
          <div key={label} className={`flex items-center gap-4 p-4 rounded-xl bg-[#0b111a] border ${border}`}>
            <div className={`p-2.5 rounded-lg bg-white/5 border border-white/5 ${color}`}>
              <Icon className="w-5 h-5" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{value}</p>
              <p className="text-xs text-gray-500 mt-0.5">{label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* ── Barra de Filtros ───────────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input
            type="text"
            placeholder="Buscar por título, alvo ou tipo..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full bg-[#0b111a] border border-white/10 rounded-lg pl-9 pr-4 py-2.5 text-sm text-white placeholder-gray-500 outline-none focus:border-indigo-500 transition-colors"
          />
        </div>
        <div className="relative">
          <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500 pointer-events-none" />
          <select
            value={riskFilter}
            onChange={e => setRiskFilter(e.target.value)}
            className="appearance-none bg-[#0b111a] border border-white/10 rounded-lg pl-9 pr-8 py-2.5 text-sm text-gray-200 outline-none focus:border-indigo-500 transition-colors cursor-pointer"
          >
            <option value="ALL">Todos os Riscos</option>
            <option value="CRITICAL">Crítico</option>
            <option value="HIGH">Alto</option>
            <option value="MEDIUM">Médio</option>
            <option value="LOW">Baixo</option>
            <option value="CLEAN">Seguro</option>
          </select>
          <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-500 pointer-events-none" />
        </div>
      </div>

      {/* ── DataGrid ────────────────────────────────────────────────────── */}
      <div className="flex-1 rounded-xl border border-white/5 bg-[#0b111a] overflow-hidden">
        {/* Header da Tabela */}
        <div className="grid grid-cols-[1fr_1.5fr_1.5fr_auto_auto] gap-4 px-5 py-3 border-b border-white/5 bg-black/20">
          {[
            { icon: Clock,      label: 'Data' },
            { icon: Target,     label: 'Alvo (Commit / Projeto)' },
            { icon: Tag,        label: 'Tipo de Relatório' },
            { icon: TrendingUp, label: 'Risco' },
            { icon: Download,   label: 'Ação' },
          ].map(({ icon: Icon, label }) => (
            <div key={label} className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-widest text-gray-500">
              <Icon className="w-3 h-3" />
              {label}
            </div>
          ))}
        </div>

        {/* Body */}
        <div className="divide-y divide-white/5">
          {loading ? (
            <div className="flex flex-col items-center justify-center py-24 gap-3 text-gray-500">
              <div className="w-6 h-6 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin" />
              <p className="text-sm">Carregando laudos...</p>
            </div>
          ) : error ? (
            <div className="flex flex-col items-center justify-center py-24 gap-3 text-red-400">
              <ShieldAlert className="w-8 h-8 opacity-60" />
              <p className="text-sm">{error}</p>
              <button onClick={fetchReportsList} className="text-xs text-indigo-400 hover:text-indigo-300 underline underline-offset-2">
                Tentar novamente
              </button>
            </div>
          ) : visibleReports.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-24 gap-3 text-gray-600">
              <FileText className="w-10 h-10 opacity-30" />
              <p className="text-sm">Nenhum laudo encontrado para os filtros selecionados.</p>
            </div>
          ) : (
            visibleReports.map((report, idx) => (
              <div
                key={report.id}
                className="grid grid-cols-[1fr_1.5fr_1.5fr_auto_auto] gap-4 items-center px-5 py-4 hover:bg-white/[0.02] transition-colors group"
              >
                {/* Data */}
                <div className="flex flex-col gap-0.5">
                  <span className="text-[12px] text-gray-300 font-mono tabular-nums">
                    {formatDate(report.completed_at)}
                  </span>
                  <span className="text-[10px] text-gray-600">
                    #{String(idx + 1).padStart(3, '0')} · {report.id?.slice(-8)}
                  </span>
                </div>

                {/* Alvo */}
                <div className="flex flex-col gap-0.5 min-w-0">
                  <span className="text-[12px] text-white font-medium truncate" title={report.title}>
                    {report.title}
                  </span>
                  <span className="text-[10px] text-indigo-400 font-mono truncate" title={report.target}>
                    {report.target_label || report.target || '—'}
                  </span>
                </div>

                {/* Tipo */}
                <div className="flex flex-col gap-0.5 min-w-0">
                  <span className="text-[12px] text-gray-300 truncate">{report.type || '—'}</span>
                  <span className="text-[10px] text-gray-600 truncate">{report.standard || '—'}</span>
                </div>

                {/* Risco */}
                <div>
                  <RiskBadge risk={report.risk} />
                </div>

                {/* Ação */}
                <div className="flex items-center gap-2">
                  <div className="flex rounded-lg overflow-hidden border border-indigo-500/20 bg-indigo-600/5">
                    <button
                      onClick={() => handleDownloadPDF(report.id)}
                      title="Baixar laudo em PDF"
                      className="flex items-center gap-1 px-2.5 py-1.5 hover:bg-indigo-600/25 border-r border-indigo-500/20 text-indigo-400 hover:text-indigo-200 text-[10px] font-bold transition-all"
                    >
                      📄 PDF
                    </button>
                    <button
                      onClick={() => handleDownloadJSON(report.id)}
                      title="Baixar laudo em JSON"
                      className="flex items-center gap-1 px-2.5 py-1.5 hover:bg-indigo-600/25 text-indigo-400 hover:text-indigo-200 text-[10px] font-bold transition-all"
                    >
                      📦 JSON
                    </button>
                  </div>
                  <button
                    onClick={() => handleDelete(report.id, report.title)}
                    title="Excluir laudo permanentemente"
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-600/10 hover:bg-red-600/30 border border-red-500/20 hover:border-red-500/50 text-red-400 hover:text-red-200 text-[11px] font-semibold transition-all"
                  >
                    <Trash2 className="w-3 h-3" />
                    Excluir
                  </button>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Footer */}
        {!loading && !error && visibleReports.length > 0 && (
          <div className="px-5 py-3 border-t border-white/5 bg-black/10 text-[11px] text-gray-600 flex items-center justify-between">
            <span>
              Exibindo <span className="text-gray-400 font-medium">{visibleReports.length}</span> de{' '}
              <span className="text-gray-400 font-medium">{reports.length}</span> laudos
            </span>
            <span className="font-mono">PreviSwit AI-ASPM · Compliance Engine v1.0</span>
          </div>
        )}
      </div>
    </div>
  );
}

/**
 * API pública para consumo por outras abas/componentes React:
 *
 * Exemplo de uso no RiskGraphCanvas.jsx após conclusão de scan SAST:
 *
 *   if (window.previswit?.reports?.receive) {
 *     window.previswit.reports.receive({
 *       title:        `Auditoria SAST — Commit ${sha.slice(0,7)}`,
 *       target:       `commit:${sha}`,
 *       target_label: `${sha.slice(0,7)} — ${branchName}`,
 *       type:         'SAST Técnico',
 *       standard:     'OWASP Top 10 / CWE',
 *       risk:         data.vulnerable ? 'HIGH' : 'CLEAN',
 *     });
 *   }
 */
