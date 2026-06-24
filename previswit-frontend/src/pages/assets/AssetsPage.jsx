import React, { useState, useEffect } from 'react';
import { NavLink } from 'react-router-dom';
import { GitBranch, Cloud, Box, Monitor, Globe, Server, TrendingUp, ShieldAlert } from 'lucide-react';

const API = '/api/v1';

// Mapeamento de ícones por tipo (backend retorna string, frontend mapeia para JSX)
const ICON_MAP = {
  'git-branch': <GitBranch className="w-5 h-5" />,
  'cloud': <Cloud className="w-5 h-5" />,
  'box': <Box className="w-5 h-5" />,
  'monitor': <Monitor className="w-5 h-5" />,
  'globe': <Globe className="w-5 h-5" />,
};

// Paleta de cores por color-key retornada pelo backend
const COLOR_MAP = {
  purple: { bg: 'bg-purple-500/10', border: 'border-purple-500/20', text: 'text-purple-400' },
  sky: { bg: 'bg-sky-500/10', border: 'border-sky-500/20', text: 'text-sky-400' },
  cyan: { bg: 'bg-cyan-500/10', border: 'border-cyan-500/20', text: 'text-cyan-400' },
  amber: { bg: 'bg-amber-500/10', border: 'border-amber-500/20', text: 'text-amber-400' },
  emerald: { bg: 'bg-emerald-500/10', border: 'border-emerald-500/20', text: 'text-emerald-400' },
};

// Rota do frontend por tipo de ativo
const TYPE_TO_PATH = {
  REPOSITORY: '/assets/repositories',
  CLOUD: '/assets/cloud',
  CONTAINER: '/assets/containers',
  VM: '/assets/vms',
  DOMAIN: '/assets/domains',
};

// ── Categoria cards para o resumo ─────────────────────────────────────────────
const CATEGORY_CARDS = [
  {
    path: '/assets/repositories',
    label: 'Repositórios',
    hint: 'GitHub · GitLab · Bitbucket',
    icon: <GitBranch className="w-5 h-5" />,
    typeFilter: 'REPOSITORY',
    colorBg: 'bg-purple-500/10',
    colorBorder: 'border-purple-500/20',
    colorText: 'text-purple-400',
  },
  {
    path: '/assets/cloud',
    label: 'Cloud',
    hint: 'AWS · Azure · GCP',
    icon: <Cloud className="w-5 h-5" />,
    typeFilter: 'CLOUD',
    colorBg: 'bg-sky-500/10',
    colorBorder: 'border-sky-500/20',
    colorText: 'text-sky-400',
  },
  {
    path: '/assets/containers',
    label: 'Contêineres',
    hint: 'Imagens Docker · Kubernetes',
    icon: <Box className="w-5 h-5" />,
    typeFilter: 'CONTAINER',
    colorBg: 'bg-cyan-500/10',
    colorBorder: 'border-cyan-500/20',
    colorText: 'text-cyan-400',
  },
  {
    path: '/assets/vms',
    label: 'Máquinas Virtuais',
    hint: 'VMs · Instâncias · Bare Metal',
    icon: <Monitor className="w-5 h-5" />,
    typeFilter: 'VM',
    colorBg: 'bg-amber-500/10',
    colorBorder: 'border-amber-500/20',
    colorText: 'text-amber-400',
  },
  {
    path: '/assets/domains',
    label: 'Domínios & APIs',
    hint: 'Endpoints expostos · APIs públicas',
    icon: <Globe className="w-5 h-5" />,
    typeFilter: 'DOMAIN',
    colorBg: 'bg-emerald-500/10',
    colorBorder: 'border-emerald-500/20',
    colorText: 'text-emerald-400',
  },
];

export default function AssetsPage() {
  const [summary, setSummary] = useState(null);   // GET /assets/summary
  const [assets, setAssets] = useState([]);     // GET /assets/ (inventário completo)
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);

  const fetchData = async () => {
    setLoading(true);
    setError(false);
    try {
      const [sumRes, listRes] = await Promise.all([
        fetch(API + '/assets/summary'),
        fetch(API + '/assets/'),
      ]);
      if (sumRes.ok) setSummary(await sumRes.json());
      if (listRes.ok) setAssets((await listRes.json()).assets ?? []);
      if (!sumRes.ok && !listRes.ok) setError(true);
    } catch {
      setError(true);
    }
    setLoading(false);
  };

  useEffect(() => { fetchData(); }, []);

  const total = summary?.total ?? assets.length;
  const critical = summary?.critical ?? 0;
  const high = summary?.high ?? 0;

  return (
    <div className="flex flex-col h-full space-y-6">

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-4">
          <div className="p-3 rounded-xl bg-blue-500/10 border border-blue-500/20">
            <Server className="w-6 h-6 text-blue-400" />
          </div>
          <div>
            <h2 className="text-xl font-semibold text-white">Resumo de Ativos &amp; Produtos</h2>
            <p className="text-sm text-gray-500 mt-0.5">
              Visão geral do inventário de ativos digitais — clique em uma categoria para explorar.
            </p>
          </div>
        </div>
        <button
          onClick={fetchData}
          className="text-xs bg-white/5 text-gray-400 border border-white/10 px-3 py-1.5 rounded-lg hover:bg-white/10 hover:text-white transition-all"
        >
          ↻ Atualizar
        </button>
      </div>

      {/* ── KPI strip ──────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-3 gap-3">
        <div className="bg-[#0d1421] border border-white/5 rounded-xl p-5 flex items-center gap-4">
          <Server className="w-8 h-8 text-blue-400/60 shrink-0" />
          <div>
            <p className="text-[11px] text-gray-500 uppercase tracking-wider">Total de Ativos</p>
            <p className="text-3xl font-bold text-white mt-0.5">{loading ? '…' : total}</p>
          </div>
        </div>
        <div className="bg-[#0d1421] border border-white/5 rounded-xl p-5 flex items-center gap-4">
          <ShieldAlert className="w-8 h-8 text-red-400/60 shrink-0" />
          <div>
            <p className="text-[11px] text-gray-500 uppercase tracking-wider">Críticos</p>
            <p className="text-3xl font-bold text-red-400 mt-0.5">{loading ? '…' : critical}</p>
          </div>
        </div>
        <div className="bg-[#0d1421] border border-white/5 rounded-xl p-5 flex items-center gap-4">
          <TrendingUp className="w-8 h-8 text-orange-400/60 shrink-0" />
          <div>
            <p className="text-[11px] text-gray-500 uppercase tracking-wider">Superfície de Ataque</p>
            <p className="text-3xl font-bold text-orange-400 mt-0.5">{loading ? '…' : total}</p>
          </div>
        </div>
      </div>

      {/* ── Categoria cards — inventário por tipo (dados do /assets/summary) ── */}
      <div>
        <p className="text-xs font-semibold uppercase tracking-widest text-gray-600 mb-3">
          Explorar por Categoria
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
          {summary
            ? Object.entries(summary.by_type).map(([typeKey, cat]) => {
              const colors = COLOR_MAP[cat.color] ?? COLOR_MAP.purple;
              const icon = ICON_MAP[cat.icon] ?? <Server className="w-5 h-5" />;
              const path = TYPE_TO_PATH[typeKey] ?? '/assets';
              return (
                <NavLink
                  key={typeKey}
                  to={path}
                  className="group flex items-center gap-4 p-4 bg-[#0d1421] border border-white/5 rounded-xl hover:border-white/10 hover:bg-[#111b2e] transition-all duration-150"
                >
                  {/* Icon */}
                  <div className={`p-2.5 rounded-lg border ${colors.bg} ${colors.border} shrink-0`}>
                    <span className={colors.text}>{icon}</span>
                  </div>

                  {/* Text */}
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold text-white group-hover:text-gray-100">{cat.label}</p>
                    <p className="text-[11px] text-gray-500 mt-0.5">{cat.hint}</p>
                  </div>

                  {/* Count + criticidade pill */}
                  <div className="shrink-0 text-right">
                    <p className={`text-lg font-bold ${colors.text}`}>{cat.count}</p>
                    <p className="text-[10px] text-gray-600">
                      {cat.critical > 0 ? `${cat.critical} crítico${cat.critical > 1 ? 's' : ''}` : 'ativos'}
                    </p>
                  </div>
                </NavLink>
              );
            })
            : /* Skeleton enquanto summary carrega */
            Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="h-[76px] bg-[#0d1421] border border-white/5 rounded-xl animate-pulse" />
            ))
          }
        </div>
      </div>


      {/* ── Inventário geral (todos os ativos) ────────────────────────────── */}
      <div className="flex-1 min-h-0 flex flex-col bg-[#0d1421] border border-white/5 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-white/5 flex items-center justify-between shrink-0">
          <div>
            <p className="text-sm font-semibold text-gray-300">Inventário Completo</p>
            <p className="text-[11px] text-gray-600 mt-0.5">Todos os ativos registrados na plataforma</p>
          </div>
          <span className="text-xs px-2 py-1 bg-white/5 border border-white/10 rounded-full text-gray-400">
            {loading ? '…' : `${total} ativo${total !== 1 ? 's' : ''}`}
          </span>
        </div>

        <div className="p-4 overflow-y-auto flex-1">
          {loading && (
            <div className="flex flex-col items-center justify-center py-16 gap-3">
              <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
              <p className="text-sm text-gray-500">Carregando ativos…</p>
            </div>
          )}
          {error && !loading && (
            <p className="text-red-400 text-sm text-center py-12">Erro ao conectar com a API.</p>
          )}
          {!loading && !error && assets.length === 0 && (
            <div className="flex flex-col items-center justify-center py-16 gap-3">
              <div className="p-4 rounded-xl bg-white/3 border border-white/5">
                <Server className="w-8 h-8 text-gray-600" />
              </div>
              <p className="text-sm text-gray-600">Nenhum ativo cadastrado ainda.</p>
              <p className="text-xs text-gray-700">
                Adicione ativos via API ou importe via scanner.
              </p>
            </div>
          )}
          {!loading && !error && assets.length > 0 && (
            <div className="space-y-1">
              {assets.map((a, i) => (
                <div
                  key={i}
                  className="flex items-center justify-between py-3 px-3 border border-transparent hover:border-white/5 hover:bg-white/2 rounded-lg transition-all"
                >
                  <div className="flex items-center gap-3">
                    <div className="w-1.5 h-1.5 rounded-full bg-blue-500/50 shrink-0" />
                    <div>
                      <p className="text-sm text-white font-medium">{a.name}</p>
                      <p className="text-xs text-gray-500 mt-0.5">
                        {a.asset_type || 'N/A'}{a.host ? ` · ${a.host}` : ''}
                      </p>
                    </div>
                  </div>
                  <span
                    className={`text-xs px-2 py-1 rounded-full border ${a.criticality === 'CRITICAL'
                        ? 'bg-red-500/10 text-red-400 border-red-500/20'
                        : a.criticality === 'HIGH'
                          ? 'bg-orange-500/10 text-orange-400 border-orange-500/20'
                          : 'bg-gray-500/10 text-gray-400 border-gray-500/20'
                      }`}
                  >
                    {a.criticality || 'N/A'}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

    </div>
  );
}
