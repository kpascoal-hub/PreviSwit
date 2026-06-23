import React, { useState, useEffect } from 'react';
import { useParams, useLocation, NavLink } from 'react-router-dom';
import { GitBranch, Cloud, Box, Monitor, Globe, Server, ArrowLeft } from 'lucide-react';

const API = '/api/v1';

// ── Category metadata ─────────────────────────────────────────────────────────
const CATEGORIES = {
  repositories: {
    label: 'Repositórios',
    subtitle: 'GitHub · GitLab · Bitbucket',
    icon: <GitBranch className="w-6 h-6" />,
    color: 'purple',
    colorClass: 'text-purple-400 bg-purple-500/10 border-purple-500/20',
    emptyMsg: 'Nenhum repositório mapeado. Conecte sua integração GitHub ou GitLab.',
    typeFilter: 'REPOSITORY',
  },
  cloud: {
    label: 'Cloud',
    subtitle: 'AWS · Azure · GCP',
    icon: <Cloud className="w-6 h-6" />,
    color: 'sky',
    colorClass: 'text-sky-400 bg-sky-500/10 border-sky-500/20',
    emptyMsg: 'Nenhum ativo cloud mapeado ainda.',
    typeFilter: 'CLOUD',
  },
  containers: {
    label: 'Contêineres',
    subtitle: 'Imagens Docker · Kubernetes',
    icon: <Box className="w-6 h-6" />,
    color: 'cyan',
    colorClass: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20',
    emptyMsg: 'Nenhuma imagem de container registrada.',
    typeFilter: 'CONTAINER',
  },
  vms: {
    label: 'Máquinas Virtuais',
    subtitle: 'VMs · Instâncias EC2 · Bare Metal',
    icon: <Monitor className="w-6 h-6" />,
    color: 'amber',
    colorClass: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
    emptyMsg: 'Nenhuma VM ou instância registrada.',
    typeFilter: 'VM',
  },
  domains: {
    label: 'Domínios & APIs',
    subtitle: 'Endpoints expostos · APIs públicas',
    icon: <Globe className="w-6 h-6" />,
    color: 'emerald',
    colorClass: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
    emptyMsg: 'Nenhum domínio ou API registrada.',
    typeFilter: 'DOMAIN',
  },
};

// ── Sub-nav breadcrumb pills ─────────────────────────────────────────────────
const SUB_LINKS = [
  { path: '/assets/repositories', label: 'Repositórios' },
  { path: '/assets/cloud',        label: 'Cloud' },
  { path: '/assets/containers',   label: 'Contêineres' },
  { path: '/assets/vms',          label: 'Máquinas Virtuais' },
  { path: '/assets/domains',      label: 'Domínios & APIs' },
];

export default function AssetsCategoryPage() {
  const { category } = useParams();          // e.g. "repositories"

  // Map frontend URL slug → API type key
  const SLUG_TO_TYPE = {
    repositories: 'REPOSITORY',
    cloud:        'CLOUD',
    containers:   'CONTAINER',
    vms:          'VM',
    domains:      'DOMAIN',
  };
  const apiType = SLUG_TO_TYPE[category];

  const [data,    setData]    = useState(null);   // full API response
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState(false);

  const fetchCategory = async () => {
    if (!apiType) return;
    setLoading(true);
    setError(false);
    try {
      const res = await fetch(`/api/v1/assets/category/${apiType}`);
      if (res.ok) {
        setData(await res.json());
      } else {
        setError(true);
      }
    } catch {
      setError(true);
    }
    setLoading(false);
  };

  useEffect(() => { fetchCategory(); }, [category]);

  if (!apiType) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-gray-500">
        <Server className="w-10 h-10 mb-4 opacity-30" />
        <p>Categoria não encontrada.</p>
      </div>
    );
  }

  const meta   = CATEGORIES[category] ?? {};
  const assets = data?.assets ?? [];
  const counts = data?.counts ?? {};


  return (
    <div className="flex flex-col h-full space-y-5">

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-4">
          <div className={`p-3 rounded-xl border ${meta.colorClass}`}>
            {meta.icon}
          </div>
          <div>
            <div className="flex items-center gap-2 mb-0.5">
              <NavLink
                to="/assets"
                className="text-xs text-gray-600 hover:text-gray-400 transition-colors flex items-center gap-1"
              >
                <ArrowLeft className="w-3 h-3" />
                Ativos & Produtos
              </NavLink>
              <span className="text-gray-700">/</span>
              <span className="text-xs text-gray-400 font-medium">{meta.label}</span>
            </div>
            <h2 className="text-xl font-semibold text-white">{meta.label}</h2>
            <p className="text-sm text-gray-500 mt-0.5">{meta.subtitle}</p>
          </div>
        </div>

        <button
          onClick={fetchCategory}
          className="text-xs bg-white/5 text-gray-400 border border-white/10 px-3 py-1.5 rounded-lg hover:bg-white/10 hover:text-white transition-all"
        >
          ↻ Atualizar
        </button>
      </div>

      {/* ── Sub-category quick-nav pills ──────────────────────────────────── */}
      <div className="flex items-center gap-2 flex-wrap">
        {SUB_LINKS.map(link => (
          <NavLink
            key={link.path}
            to={link.path}
            className={({ isActive }) =>
              `px-3 py-1 text-xs font-medium rounded-full border transition-all duration-150 ${
                isActive
                  ? 'bg-blue-600/15 text-blue-400 border-blue-500/30'
                  : 'text-gray-500 border-white/10 hover:text-gray-300 hover:border-white/20'
              }`
            }
          >
            {link.label}
          </NavLink>
        ))}
      </div>

      {/* ── Stats strip ───────────────────────────────────────────────────── */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: 'Total',    value: loading ? '…' : assets.length,                                                    color: 'text-white' },
          { label: 'Críticos', value: loading ? '…' : assets.filter(a => a.criticality === 'CRITICAL').length,          color: 'text-red-400' },
          { label: 'Altos',    value: loading ? '…' : assets.filter(a => a.criticality === 'HIGH').length,              color: 'text-orange-400' },
        ].map(stat => (
          <div key={stat.label} className="bg-[#0d1421] border border-white/5 rounded-xl p-4">
            <p className="text-[11px] text-gray-500 uppercase tracking-wider mb-1">{stat.label}</p>
            <p className={`text-2xl font-bold ${stat.color}`}>{stat.value}</p>
          </div>
        ))}
      </div>

      {/* ── Asset list ────────────────────────────────────────────────────── */}
      <div className="flex-1 min-h-0 flex flex-col bg-[#0d1421] border border-white/5 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-white/5 flex items-center justify-between shrink-0">
          <p className="text-sm font-semibold text-gray-300">
            {loading ? 'Carregando…' : `${assets.length} ativo${assets.length !== 1 ? 's' : ''} encontrado${assets.length !== 1 ? 's' : ''}`}
          </p>
          <span className={`text-xs px-2 py-0.5 rounded-full border ${meta.colorClass}`}>
            {meta.label}
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
            <p className="text-red-400 text-sm text-center py-12">
              Erro ao conectar com a API. Verifique se o servidor está rodando.
            </p>
          )}

          {!loading && !error && assets.length === 0 && (
            <div className="flex flex-col items-center justify-center py-16 gap-3 text-center">
              <div className={`p-4 rounded-xl border ${meta.colorClass} opacity-40`}>
                {meta.icon}
              </div>
              <p className="text-sm text-gray-500 max-w-xs">{meta.emptyMsg}</p>
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
                    <div className={`p-1.5 rounded-lg border ${meta.colorClass}`}>
                      {React.cloneElement(meta.icon, { className: 'w-3.5 h-3.5' })}
                    </div>
                    <div>
                      <p className="text-sm text-white font-medium">{a.name}</p>
                      <p className="text-xs text-gray-500 mt-0.5">{a.host || a.url || '—'}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {a.tags && a.tags.length > 0 && (
                      <span className="text-xs text-gray-600">{a.tags.slice(0, 2).join(', ')}</span>
                    )}
                    <span
                      className={`text-xs px-2 py-1 rounded-full border ${
                        a.criticality === 'CRITICAL'
                          ? 'bg-red-500/10 text-red-400 border-red-500/20'
                          : a.criticality === 'HIGH'
                          ? 'bg-orange-500/10 text-orange-400 border-orange-500/20'
                          : 'bg-gray-500/10 text-gray-400 border-gray-500/20'
                      }`}
                    >
                      {a.criticality || 'N/A'}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
