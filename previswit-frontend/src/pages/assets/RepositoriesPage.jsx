/**
 * PreviSwit AI-ASPM — Gestão de Repositórios de Código
 * =====================================================
 * Página dedicada à seção "Repositórios" dentro de "Ativos & Produtos".
 *
 * Estrutura:
 *   - Cabeçalho com título e botão "Conectar GitHub"
 *   - Grid dinâmico (id="repositories-grid") → vazio no HTML; populado via API
 *   - Empty state (id="repositories-empty-state") → exibido enquanto sem dados
 *   - async fetchRepositories() → busca dados reais em GET /api/v1/github/repos
 *     Schema retornado: { repos: [{ name, language, updated_at }] }
 *
 * Regra de Ouro: ZERO dados mockados. Tudo vem da API GitHub via backend.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { NavLink } from 'react-router-dom';
import {
  GitBranch, ArrowLeft, Link2, RefreshCw,
  Folder, AlertTriangle, ExternalLink,
  Lock, Unlock, GitFork, Star, Clock, Settings,
  FileText, ChevronDown, CheckCircle
} from 'lucide-react';
import RiskGraphCanvas from './RiskGraphCanvas';

const API = '/api/v1';

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Formata data ISO para exibição legível em pt-BR. */
function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('pt-BR', {
    day: '2-digit', month: 'short', year: 'numeric',
  });
}

/** Badge de criticidade. */
function CriticalityBadge({ value }) {
  const map = {
    CRITICAL: 'bg-red-500/10 text-red-400 border-red-500/25',
    HIGH: 'bg-orange-500/10 text-orange-400 border-orange-500/25',
    MEDIUM: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/25',
    LOW: 'bg-blue-500/10 text-blue-400 border-blue-500/25',
  };
  return (
    <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${map[value] ?? 'bg-gray-500/10 text-gray-400 border-gray-500/25'}`}>
      {value ?? 'N/A'}
    </span>
  );
}

// ── Repository Card ───────────────────────────────────────────────────────────

/**
 * Card de repositório injetado dinamicamente no repositories-grid.
 * Props vêm do endpoint GET /api/v1/github/repos.
 * Schema: { name: string, language: string|null, updated_at: string }
 */
function RepositoryCard({ repo, openRiskGraph }) {
  // Slug único baseado no nome (GitHub não retorna IDs numéricos no mapeamento limpo)
  const slug = repo.name?.toLowerCase().replace(/[^a-z0-9]/g, '-') ?? 'repo';
  const repoUrl = `https://github.com/${repo.name}.git`;

  const [showScheduleModal, setShowScheduleModal] = useState(false);
  const [intervalValue, setIntervalValue] = useState("30");
  const [intervalUnit, setIntervalUnit] = useState("MINUTES"); // "MINUTES" | "HOURS" | "DAYS"
  const [runOnce, setRunOnce] = useState(true);
  const [selectedAiLevel, setSelectedAiLevel] = useState("EXECUTIVO");
  const [scanStatus, setScanStatus] = useState(null); // 'PENDING' | 'RUNNING' | 'CONCLUÍDO' | 'ERROR'
  const [scanId, setScanId] = useState(null);
  const [scanData, setScanData] = useState(null);
  const [isGeneratingPdf, setIsGeneratingPdf] = useState(false);
  const [toast, setToast] = useState(null);

  const showToast = (msg) => {
    setToast(msg);
    setTimeout(() => setToast(null), 3500);
  };

  // Hook Polling: Verifica o status do scan no backend
  useEffect(() => {
    let interval;
    if (scanId && (scanStatus === 'PENDING' || scanStatus === 'RUNNING')) {
      interval = setInterval(async () => {
        try {
          const res = await fetch(`${API}/sast/scan-status/${scanId}`);
          if (res.ok) {
            const data = await res.json();
            setScanStatus(data.status);
            if (data.status === 'CONCLUÍDO') {
              setScanData(data.data);
              clearInterval(interval);
            } else if (data.status === 'ERROR') {
              clearInterval(interval);
            }
          }
        } catch (e) {
          console.error("Erro no polling do scan:", e);
        }
      }, 3000);
    }
    return () => clearInterval(interval);
  }, [scanId, scanStatus]);

  const handleStartScan = async () => {
    setShowScheduleModal(false);
    setScanStatus('PENDING');
    
    // Cálculo do tempo sob demanda em minutos
    let intervalMinutes = 0;
    if (!runOnce) {
      const val = parseInt(intervalValue, 10) || 0;
      if (intervalUnit === "MINUTES") {
        intervalMinutes = val;
      } else if (intervalUnit === "HOURS") {
        intervalMinutes = val * 60;
      } else if (intervalUnit === "DAYS") {
        intervalMinutes = val * 60 * 24;
      }
    }

    try {
      const geminiKey = sessionStorage.getItem('X-Gemini-Key') || '';
      const res = await fetch(`${API}/sast/schedule`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Gemini-Key': geminiKey
        },
        body: JSON.stringify({
          repo_url: repoUrl,
          target_name: repo.name,
          interval_minutes: intervalMinutes,
          ai_summary_level: selectedAiLevel
        })
      });
      if (res.ok) {
        const data = await res.json();
        setScanId(data.scan_id);
        showToast("Orquestração Iniciada");
      } else {
        setScanStatus('ERROR');
        showToast("Erro ao iniciar orquestração");
      }
    } catch (e) {
      setScanStatus('ERROR');
      showToast("Erro ao iniciar orquestração");
    }
  };

  const handleGenerateComplianceReport = async () => {
    if (!scanData) return;
    setIsGeneratingPdf(true);
    try {
      const res = await fetch(`${API}/reports/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: `Conformidade ${selectedAiLevel} — ${repo.name}`,
          target: `repo:${repo.name}`,
          target_label: repo.name,
          type: 'Scan de Repositório',
          standard: selectedAiLevel === 'CONFORMIDADE' ? 'ISO 27001 / SOC2' : 'OWASP Top 10',
          risk: scanData.vulnerable ? 'HIGH' : 'CLEAN',
          compliance_model: selectedAiLevel,
          scan_data: scanData.scanner_results
        })
      });
      
      if (!res.ok) throw new Error("Erro ao salvar o relatório");
      const saved = await res.json();
      
      if (window.previswit?.reports?.receive) {
        window.previswit.reports.receive(saved.report);
      }
      showToast("Relatório salvo com sucesso! Acesse a aba de Relatórios para exportar as evidências.");
    } catch (e) {
      showToast(`Falha ao salvar relatório: ${e.message}`);
    } finally {
      setIsGeneratingPdf(false);
    }
  };

  const handleOpenDeepDive = (e) => {
    openRiskGraph(repo);
  };

  // Determina as cores e texto do badge de status
  let badgeProps = { bg: 'bg-amber-500/10', border: 'border-amber-500/30', text: 'text-amber-400', label: '⏳ Pendente de Scan', icon: '' };
  if (scanStatus === 'PENDING' || scanStatus === 'RUNNING') {
    badgeProps = { bg: 'bg-blue-500/10', border: 'border-blue-500/25', text: 'text-blue-400', label: 'Analisando...', icon: '🔄 ' };
  } else if (scanStatus === 'CONCLUÍDO' || scanData) {
    badgeProps = { bg: 'bg-emerald-500/10', border: 'border-emerald-500/30', text: 'text-emerald-400', label: '🛡️ Scan Completo', icon: '' };
  } else if (scanStatus === 'ERROR') {
    badgeProps = { bg: 'bg-red-500/10', border: 'border-red-500/25', text: 'text-red-400', label: 'Erro no Scan', icon: '⚠️ ' };
  }

  return (
    <div
      id={`repo-card-${slug}`}
      className="group flex flex-col gap-3 p-5 rounded-xl border border-white/5 bg-slate-900/50
                 hover:border-purple-500/25 hover:bg-[#111827] transition-all duration-200"
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="shrink-0 p-2 rounded-lg bg-purple-500/10 border border-purple-500/20">
            <GitBranch className="w-4 h-4 text-purple-400" />
          </div>
          <div className="min-w-0">
            <p className="text-sm font-semibold text-white truncate group-hover:text-purple-200 transition-colors">
              {repo.name}
            </p>
            <p className="text-[11px] text-gray-500 mt-0.5 truncate">
              GitHub · {repo.language ?? 'Linguagem desconhecida'}
            </p>
          </div>
        </div>
        <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${badgeProps.bg} ${badgeProps.text} ${badgeProps.border} whitespace-nowrap flex items-center gap-1`}>
          {badgeProps.icon}{badgeProps.label}
        </span>
      </div>

      {/* Meta strip */}
      <div className="flex items-center gap-3 text-[11px] text-gray-600 mt-auto pt-2 border-t border-white/5">
        {repo.language && (
          <span className="flex items-center gap-1 text-blue-400/70">
            <GitFork className="w-3 h-3" />
            {repo.language}
          </span>
        )}
        <span className="flex items-center gap-1 ml-auto">
          <Clock className="w-3 h-3" />
          {fmtDate(repo.updated_at)}
        </span>
      </div>

      {/* Primary Actions */}
      <div className="flex gap-2 relative">
        <button
          id={`btn-scan-repo-${slug}`}
          onClick={() => setShowScheduleModal(true)}
          className="flex-1 flex items-center justify-center gap-1.5 py-1.5 text-xs font-medium
                     rounded-lg border border-purple-500/25 text-purple-400
                     hover:bg-purple-500/10 hover:border-purple-500/50 transition-all duration-150"
        >
          <Star className="w-3 h-3" />
          Scan SAST
        </button>

        {showScheduleModal && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70 backdrop-blur-md">
            <div className="w-full max-w-lg bg-[#060b13] border border-slate-800 rounded-2xl p-6 shadow-2xl flex flex-col gap-6">
              
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-purple-500/10 border border-purple-500/20">
                  <Star className="w-5 h-5 text-purple-400" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-white">Configuração de Orquestração SAST</h3>
                  <p className="text-[11px] text-gray-500 mt-0.5">Alvo: {repo.name}</p>
                </div>
              </div>

              <div className="space-y-5">
                {/* Campo 1: Tempo Sob Demanda */}
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <label className="block text-xs font-semibold text-gray-400">
                      Frequência de Varredura
                    </label>
                    <label className="flex items-center gap-2 text-xs text-gray-300 cursor-pointer select-none">
                      <input
                        type="checkbox"
                        checked={runOnce}
                        onChange={(e) => setRunOnce(e.target.checked)}
                        className="rounded border-white/10 bg-[#111827] text-purple-600 focus:ring-purple-500/50"
                      />
                      Rodar apenas uma vez agora
                    </label>
                  </div>
                  
                  {!runOnce && (
                    <div className="flex gap-2 animate-in fade-in-50 duration-150">
                      <div className="flex-1">
                        <input
                          type="number"
                          placeholder="Ex: 30"
                          value={intervalValue}
                          onChange={(e) => setIntervalValue(e.target.value)}
                          className="w-full bg-[#111827] border border-white/10 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-purple-500/50 transition-colors"
                        />
                      </div>
                      <div className="relative w-1/3">
                        <select
                          value={intervalUnit}
                          onChange={(e) => setIntervalUnit(e.target.value)}
                          className="w-full appearance-none bg-[#111827] border border-white/10 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-purple-500/50 transition-colors"
                        >
                          <option value="MINUTES">Minutos</option>
                          <option value="HOURS">Horas</option>
                          <option value="DAYS">Dias</option>
                        </select>
                        <ChevronDown className="w-4 h-4 text-gray-500 absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                      </div>
                    </div>
                  )}
                </div>

                {/* Campo 2: Foco da IA (Radio Cards) */}
                <div className="space-y-3">
                  <label className="block text-xs font-semibold text-gray-400">
                    Foco da Inteligência Artificial
                  </label>
                  <div className="grid grid-cols-1 gap-2.5">
                    {/* Card 1: Executivo */}
                    <div
                      onClick={() => setSelectedAiLevel("EXECUTIVO")}
                      className={`flex items-start gap-3 p-3 rounded-xl border cursor-pointer transition-all duration-200 bg-[#0d1421]/60
                                  ${selectedAiLevel === "EXECUTIVO"
                                    ? "border-purple-500/50 bg-[#111827]/80 text-white"
                                    : "border-white/5 text-gray-400 hover:border-white/15"}`}
                    >
                      <span className="text-sm shrink-0">📊</span>
                      <div className="min-w-0">
                        <p className="text-xs font-bold">Visão Executiva</p>
                        <p className="text-[10px] text-gray-500 mt-0.5 leading-relaxed">Foco em riscos de negócio, conformidade regulatória e impactos estratégicos gerais.</p>
                      </div>
                    </div>

                    {/* Card 2: Técnico */}
                    <div
                      onClick={() => setSelectedAiLevel("TECNICO")}
                      className={`flex items-start gap-3 p-3 rounded-xl border cursor-pointer transition-all duration-200 bg-[#0d1421]/60
                                  ${selectedAiLevel === "TECNICO"
                                    ? "border-purple-500/50 bg-[#111827]/80 text-white"
                                    : "border-white/5 text-gray-400 hover:border-white/15"}`}
                    >
                      <span className="text-sm shrink-0">⚙️</span>
                      <div className="min-w-0">
                        <p className="text-xs font-bold">Visão Técnica</p>
                        <p className="text-[10px] text-gray-500 mt-0.5 leading-relaxed">Foco em vulnerabilidades do código, referências de CWEs/OWASP e instruções diretas de refatoração.</p>
                      </div>
                    </div>

                    {/* Card 3: Conformidade */}
                    <div
                      onClick={() => setSelectedAiLevel("CONFORMIDADE")}
                      className={`flex items-start gap-3 p-3 rounded-xl border cursor-pointer transition-all duration-200 bg-[#0d1421]/60
                                  ${selectedAiLevel === "CONFORMIDADE"
                                    ? "border-purple-500/50 bg-[#111827]/80 text-white"
                                    : "border-white/5 text-gray-400 hover:border-white/15"}`}
                    >
                      <span className="text-sm shrink-0">🛡️</span>
                      <div className="min-w-0">
                        <p className="text-xs font-bold">Visão de Conformidade</p>
                        <p className="text-[10px] text-gray-500 mt-0.5 leading-relaxed">Mapeia achados de segurança diretamente com os controles de frameworks como ISO 27001 e SOC2.</p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Footer */}
              <div className="flex gap-3 mt-2">
                <button
                  onClick={() => setShowScheduleModal(false)}
                  className="flex-1 py-2.5 rounded-lg border border-white/10 text-gray-400 text-xs font-medium hover:bg-white/5 hover:text-white transition-all"
                >
                  Cancelar
                </button>
                <button
                  onClick={handleStartScan}
                  className="flex-[1.5] py-2.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold shadow-lg shadow-purple-500/20 transition-all flex items-center justify-center gap-1.5"
                >
                  🚀 Iniciar Orquestração
                </button>
              </div>

            </div>
          </div>
        )}

        <button
          onClick={handleOpenDeepDive}
          className="flex-1 flex items-center justify-center gap-1.5 py-1.5 text-xs font-medium
                     rounded-lg border border-teal-500/25 text-teal-400
                     hover:bg-teal-500/10 hover:border-teal-500/50 transition-all duration-150"
          title="Abrir Grafo de Risco (Deep Dive)"
        >
          <Settings className="w-3 h-3" />
          Deep Dive
        </button>
      </div>

      {/* Compliance Action */}
      <div className="mt-1">
        <button
          onClick={handleGenerateComplianceReport}
          disabled={scanStatus !== 'CONCLUÍDO' || isGeneratingPdf}
          className="w-full flex items-center justify-center gap-1.5 py-1.5 text-xs font-medium
                     rounded-lg border border-white/10 bg-white/5 text-gray-400
                     hover:bg-white/10 hover:text-white transition-all duration-150
                     disabled:opacity-30 disabled:cursor-not-allowed"
          title="Gera um PDF Executivo do scan concluído"
        >
          {isGeneratingPdf ? <RefreshCw className="w-3 h-3 animate-spin" /> : <FileText className="w-3 h-3" />}
          📄 Gerar Relatório de Conformidade
        </button>
      </div>

      {/* Local Toast Cyber Dark */}
      {toast && (
        <div className="fixed bottom-6 right-6 z-[500] flex items-center gap-2 px-4 py-3 rounded-lg shadow-2xl border border-purple-500/30 bg-[#0d1421]/95 backdrop-blur-md text-xs font-medium text-purple-200 animate-in slide-in-from-bottom-2">
          <CheckCircle className="w-4 h-4 text-purple-400 shrink-0" />
          {toast}
        </div>
      )}
    </div>
  );
}

// ── Empty State ───────────────────────────────────────────────────────────────

function RepositoriesEmptyState({ onConnect }) {
  return (
    <div
      id="repositories-empty-state"
      className="flex flex-col items-center justify-center p-10 mt-6
                 border border-dashed border-slate-800 rounded-xl
                 bg-slate-900/20 text-slate-500"
    >
      <div className="p-4 rounded-xl bg-white/3 border border-white/5 mb-4">
        <Folder className="w-10 h-10 text-gray-600" />
      </div>
      <p className="text-sm font-medium text-gray-400 text-center">
        Nenhum repositório sincronizado.
      </p>
      <p className="text-xs text-gray-600 text-center mt-1 max-w-xs">
        Clique em{' '}
        <button
          onClick={onConnect}
          className="text-purple-400 hover:underline"
        >
          Conectar GitHub
        </button>{' '}
        para importar sua base de código e começar os scans SAST.
      </p>
    </div>
  );
}

// ── Connect Modal Placeholder ─────────────────────────────────────────────────

function ConnectModal({ open, onClose, onConnectSuccess }) {
  const [tokenInput, setTokenInput] = useState('');

  const handleConnect = () => {
    if (!tokenInput.trim()) return;
    sessionStorage.setItem('GITHUB_TOKEN', tokenInput.trim());
    onConnectSuccess();
    onClose();
  };

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-md bg-[#0d1421] border border-white/10 rounded-2xl p-6 shadow-2xl">
        <div className="flex items-center gap-3 mb-4">
          <div className="p-2 rounded-lg bg-purple-500/10 border border-purple-500/20">
            <Link2 className="w-5 h-5 text-purple-400" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-white">Conectar GitHub</h3>
            <p className="text-xs text-gray-500 mt-0.5">Informe seu Personal Access Token (PAT)</p>
          </div>
        </div>

        {/* Token Input */}
        <div className="space-y-4 mb-6">
          <div>
            <label htmlFor="github-token" className="block text-xs font-medium text-gray-400 mb-1.5">
              GitHub Token
            </label>
            <input
              id="github-token"
              type="password"
              placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
              value={tokenInput}
              onChange={e => setTokenInput(e.target.value)}
              className="w-full bg-[#111827] border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-purple-500/50 focus:ring-1 focus:ring-purple-500/50 transition-all placeholder:text-gray-600"
            />
            <p className="text-[10px] text-gray-500 mt-1.5">
              O token é armazenado de forma segura apenas na sessão do seu navegador e não é enviado ao banco de dados.
            </p>
          </div>
        </div>

        <div className="flex gap-2">
          <button
            onClick={onClose}
            className="flex-1 py-2 rounded-lg border border-white/10 text-gray-400 text-sm
                       hover:bg-white/5 hover:text-white transition-all"
          >
            Cancelar
          </button>
          <button
            id="btn-oauth-confirm"
            onClick={handleConnect}
            disabled={!tokenInput.trim()}
            className="flex-1 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-sm
                       font-semibold shadow-lg shadow-purple-500/20 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Conectar
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function RepositoriesPage() {
  // ── State ────────────────────────────────────────────────────────────────
  const [repositories, setRepositories] = useState([]);   // dados vindos da API
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [lastSync, setLastSync] = useState(null);
  const [connectOpen, setConnectOpen] = useState(false);

  // View Control
  const [activeView, setActiveView] = useState('list');
  const [selectedRepo, setSelectedRepo] = useState(null);

  const openRiskGraph = useCallback((repo) => {
    setSelectedRepo(repo);
    setActiveView('canvas');
  }, []);

  // ── API ──────────────────────────────────────────────────────────────────

  /**
   * fetchRepositories — busca repositórios reais do GitHub via backend.
   *
   * Endpoint: GET /api/v1/github/repos
   * Schema retornado: { repos: [{ name, language, updated_at }] }
   * Popula: repositories-grid (via setRepositories)
   * Oculta: repositories-empty-state (quando repositories.length > 0)
   *
   * Nenhum dado mock é usado. O backend consulta o GitHub com GITHUB_TOKEN.
   * Se a API retornar lista vazia, o empty state é exibido automaticamente.
   */
  const fetchRepositories = useCallback(async () => {
    const token = sessionStorage.getItem('GITHUB_TOKEN');
    if (!token) {
      setRepositories([]);
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API}/github/repos`, {
        headers: {
          'X-GitHub-Token': token
        }
      });
      if (!res.ok) {
        if (res.status === 401) {
          sessionStorage.removeItem('GITHUB_TOKEN');
          throw new Error("Token inválido ou ausente. Reconecte seu GitHub.");
        }
        throw new Error(`HTTP ${res.status}`);
      }
      const data = await res.json();
      // O campo "repos" contém a lista mapeada retornada pelo github router
      setRepositories(data.repos ?? []);
      setLastSync(new Date());
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchRepositories(); }, [fetchRepositories]);

  // ── Render ───────────────────────────────────────────────────────────────
  const hasRepos = repositories.length > 0;

  if (activeView === 'canvas' && selectedRepo) {
    return <RiskGraphCanvas repo={selectedRepo} onBack={() => setActiveView('list')} />;
  }

  return (
    <>
      {/* Connect Modal */}
      <ConnectModal open={connectOpen} onClose={() => setConnectOpen(false)} onConnectSuccess={fetchRepositories} />

      {/* Page wrapper — id="view-repositories" mantém compatibilidade com naming do spec */}
      <section
        id="view-repositories"
        className="view-section w-full flex flex-col gap-6"
      >

        {/* ── Cabeçalho ─────────────────────────────────────────────────── */}
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-4">
            {/* Breadcrumb */}
            <div>
              <div className="flex items-center gap-1.5 mb-0.5">
                <NavLink
                  to="/assets"
                  className="text-xs text-gray-600 hover:text-gray-400 flex items-center gap-1 transition-colors"
                >
                  <ArrowLeft className="w-3 h-3" />
                  Ativos & Produtos
                </NavLink>
                <span className="text-gray-700">/</span>
                <span className="text-xs text-purple-400 font-medium">Repositórios</span>
              </div>
              <h1 className="text-xl font-semibold text-white">
                Gestão de Repositórios de Código
              </h1>
              <p className="text-sm text-gray-500 mt-0.5">
                Inventário de repositórios Git — base para scans SAST e análise de supply chain.
              </p>
            </div>
          </div>

          {/* Actions */}
          <div className="flex items-center gap-2 shrink-0">
            {lastSync && (
              <span className="text-[11px] text-gray-600">
                Sync: {lastSync.toLocaleTimeString('pt-BR')}
              </span>
            )}
            <button
              id="btn-refresh-repositories"
              onClick={fetchRepositories}
              disabled={loading}
              title="Atualizar lista"
              className="p-2 rounded-lg border border-white/8 text-gray-500 hover:text-white
                         hover:bg-white/5 hover:border-white/20 transition-all disabled:opacity-40"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>

            {/* Botão primário — Conectar GitHub */}
            <button
              id="btn-connect-github"
              onClick={() => setConnectOpen(true)}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold
                         bg-purple-600 hover:bg-purple-500 text-white
                         shadow-lg shadow-purple-500/20 transition-all duration-200"
            >
              <Link2 className="w-4 h-4" />
              Conectar GitHub
            </button>
          </div>
        </div>

        {/* ── KPI strip ─────────────────────────────────────────────────── */}
        <div className="grid grid-cols-3 gap-3">
          {[
            { label: 'Total', value: loading ? '…' : repositories.length, color: 'text-white' },
            {
              label: 'Linguagens',
              value: loading ? '…' : new Set(repositories.map(r => r.language).filter(Boolean)).size,
              color: 'text-blue-400',
            },
            {
              label: 'Sem Scan',
              value: loading ? '…' : repositories.length,
              color: 'text-amber-400',
            },
          ].map(stat => (
            <div key={stat.label} className="bg-[#0d1421] border border-white/5 rounded-xl p-4 flex items-center gap-3">
              <div className="flex-1">
                <p className="text-[11px] text-gray-500 uppercase tracking-wider">{stat.label}</p>
                <p className={`text-2xl font-bold mt-0.5 ${stat.color}`}>{stat.value}</p>
              </div>
            </div>
          ))}
        </div>

        {/* ── Error banner ──────────────────────────────────────────────── */}
        {error && !loading && (
          <div className="flex items-center gap-3 px-4 py-3 rounded-xl
                          bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>Erro ao carregar repositórios: {error}</span>
            <button
              onClick={fetchRepositories}
              className="ml-auto text-xs underline hover:no-underline"
            >
              Tentar novamente
            </button>
          </div>
        )}

        {/* ── Loading spinner ────────────────────────────────────────────── */}
        {loading && (
          <div className="flex flex-col items-center justify-center py-20 gap-3">
            <div className="w-6 h-6 border-2 border-purple-500 border-t-transparent rounded-full animate-spin" />
            <p className="text-sm text-gray-500">Sincronizando repositórios…</p>
          </div>
        )}

        {/* ── Grid dinâmico (repositories-grid) ─────────────────────────── */}
        {/* IMPORTANTE: Esta div começa VAZIA no HTML.                       */}
        {/* Os cards são injetados dinamicamente via fetchRepositories().     */}
        {!loading && hasRepos && (
          <div
            id="repositories-grid"
            className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4"
          >
            {repositories.map((repo, idx) => (
              <RepositoryCard key={repo.name ?? idx} repo={repo} openRiskGraph={openRiskGraph} />
            ))}
          </div>
        )}

        {/* ── Empty state (repositories-empty-state) ────────────────────── */}
        {/* Exibido apenas quando a API retorna lista vazia e não há erro.   */}
        {!loading && !hasRepos && !error && (
          <RepositoriesEmptyState onConnect={() => setConnectOpen(true)} />
        )}

      </section>
    </>
  );
}
