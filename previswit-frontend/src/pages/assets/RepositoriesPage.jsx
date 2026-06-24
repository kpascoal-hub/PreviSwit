/**
 * PreviSwit AI-ASPM — Gestão de Repositórios de Código
 * =====================================================
 * Página dedicada à seção "Repositórios" dentro de "Ativos & Produtos".
 *
 * Estrutura:
 *   - Cabeçalho com título e botão "🔗 Conectar GitHub"
 *   - Grid dinâmico (id="repositories-grid") → vazio no HTML; populado via API
 *   - Empty state (id="repositories-empty-state") → exibido enquanto sem dados
 *   - async fetchRepositories() → busca dados reais em /api/v1/assets/category/REPOSITORY
 *
 * Regra de Ouro: ZERO dados mockados. Tudo vem da API.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { NavLink } from 'react-router-dom';
import {
  GitBranch, ArrowLeft, Link2, RefreshCw,
  Folder, AlertTriangle, ExternalLink,
  Lock, Unlock, GitFork, Star, Clock,
} from 'lucide-react';

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
    HIGH:     'bg-orange-500/10 text-orange-400 border-orange-500/25',
    MEDIUM:   'bg-yellow-500/10 text-yellow-400 border-yellow-500/25',
    LOW:      'bg-blue-500/10 text-blue-400 border-blue-500/25',
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
 * Props vêm diretamente do schema de /api/v1/assets/category/REPOSITORY.
 */
function RepositoryCard({ repo }) {
  const cm = repo.category_meta ?? {};
  const isPrivate = cm.visibility === 'private';

  return (
    <div
      id={`repo-card-${repo.id}`}
      className="group flex flex-col gap-3 p-5 rounded-xl border border-white/5 bg-[#0d1421]
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
              {cm.provider ?? 'N/A'} · {cm.language ?? 'Linguagem desconhecida'}
            </p>
          </div>
        </div>
        <CriticalityBadge value={repo.criticality} />
      </div>

      {/* Description */}
      {repo.description && (
        <p className="text-xs text-gray-500 leading-relaxed line-clamp-2">
          {repo.description}
        </p>
      )}

      {/* Meta strip */}
      <div className="flex items-center gap-3 text-[11px] text-gray-600 mt-auto pt-2 border-t border-white/5">
        <span className="flex items-center gap-1">
          {isPrivate
            ? <Lock className="w-3 h-3 text-amber-500/70" />
            : <Unlock className="w-3 h-3 text-green-500/70" />
          }
          {isPrivate ? 'Privado' : 'Público'}
        </span>

        {cm.default_branch && (
          <span className="flex items-center gap-1">
            <GitFork className="w-3 h-3" />
            {cm.default_branch}
          </span>
        )}

        <span className="flex items-center gap-1 ml-auto">
          <Clock className="w-3 h-3" />
          {fmtDate(repo.updated_at)}
        </span>
      </div>

      {/* Actions */}
      <div className="flex gap-2">
        {cm.repo_url && (
          <a
            href={cm.repo_url}
            target="_blank"
            rel="noreferrer"
            className="flex-1 flex items-center justify-center gap-1.5 py-1.5 text-xs font-medium
                       rounded-lg border border-white/8 text-gray-400 hover:text-white hover:border-purple-500/40
                       hover:bg-purple-500/5 transition-all duration-150"
          >
            <ExternalLink className="w-3 h-3" />
            Abrir
          </a>
        )}
        <button
          id={`btn-scan-repo-${repo.id}`}
          className="flex-1 flex items-center justify-center gap-1.5 py-1.5 text-xs font-medium
                     rounded-lg border border-purple-500/25 text-purple-400
                     hover:bg-purple-500/10 hover:border-purple-500/50 transition-all duration-150"
          title="Executar scan SAST neste repositório"
        >
          <Star className="w-3 h-3" />
          Scan SAST
        </button>
      </div>
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

function ConnectModal({ open, onClose }) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-md bg-[#0d1421] border border-white/10 rounded-2xl p-6 shadow-2xl">
        <div className="flex items-center gap-3 mb-4">
          <div className="p-2 rounded-lg bg-purple-500/10 border border-purple-500/20">
            <Link2 className="w-5 h-5 text-purple-400" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-white">Conectar Provedor Git</h3>
            <p className="text-xs text-gray-500 mt-0.5">OAuth via GitHub, GitLab ou Bitbucket</p>
          </div>
        </div>

        {/* Providers */}
        <div className="space-y-2 mb-6">
          {[
            { id: 'github',    label: 'GitHub',    hint: 'github.com',    icon: '🐙', ready: true  },
            { id: 'gitlab',    label: 'GitLab',    hint: 'gitlab.com',    icon: '🦊', ready: false },
            { id: 'bitbucket', label: 'Bitbucket', hint: 'bitbucket.org', icon: '🪣', ready: false },
          ].map(p => (
            <button
              key={p.id}
              id={`btn-oauth-${p.id}`}
              disabled={!p.ready}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl border text-left
                transition-all duration-150
                ${p.ready
                  ? 'border-white/10 hover:border-purple-500/40 hover:bg-purple-500/5 cursor-pointer'
                  : 'border-white/5 opacity-40 cursor-not-allowed'
                }`}
            >
              <span className="text-xl">{p.icon}</span>
              <div>
                <p className="text-sm font-medium text-white">{p.label}</p>
                <p className="text-[11px] text-gray-500">{p.hint}</p>
              </div>
              {p.ready
                ? <span className="ml-auto text-[10px] text-green-400 border border-green-500/25 bg-green-500/10 px-2 py-0.5 rounded-full">Disponível</span>
                : <span className="ml-auto text-[10px] text-gray-600 border border-gray-700 px-2 py-0.5 rounded-full">Em breve</span>
              }
            </button>
          ))}
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
            className="flex-1 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-sm
                       font-semibold shadow-lg shadow-purple-500/20 transition-all"
          >
            Autorizar GitHub
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
  const [loading,      setLoading]      = useState(false);
  const [error,        setError]        = useState(null);
  const [lastSync,     setLastSync]     = useState(null);
  const [connectOpen,  setConnectOpen]  = useState(false);

  // ── API ──────────────────────────────────────────────────────────────────

  /**
   * fetchRepositories — busca repositórios reais da API.
   *
   * Endpoint: GET /api/v1/assets/category/REPOSITORY
   * Popula: repositories-grid (via setRepositories)
   * Oculta: repositories-empty-state (quando repositories.length > 0)
   *
   * Nenhum dado mock é usado. Se a API retornar lista vazia,
   * o empty state será exibido automaticamente.
   */
  const fetchRepositories = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API}/assets/category/REPOSITORY`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      // O campo "assets" contém a lista paginada retornada pelo backend
      setRepositories(data.assets ?? []);
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

  return (
    <>
      {/* Connect Modal */}
      <ConnectModal open={connectOpen} onClose={() => setConnectOpen(false)} />

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
              🔗 Conectar GitHub
            </button>
          </div>
        </div>

        {/* ── KPI strip ─────────────────────────────────────────────────── */}
        <div className="grid grid-cols-3 gap-3">
          {[
            { label: 'Total',    value: loading ? '…' : repositories.length,                                                    color: 'text-white'       },
            { label: 'Críticos', value: loading ? '…' : repositories.filter(r => r.criticality === 'CRITICAL').length,          color: 'text-red-400'     },
            { label: 'Privados', value: loading ? '…' : repositories.filter(r => r.category_meta?.visibility === 'private').length, color: 'text-amber-400' },
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
            {repositories.map(repo => (
              <RepositoryCard key={repo.id} repo={repo} />
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
