/**
 * PreviSwit AI-ASPM — Dashboard Bento Box
 * =========================================
 * Painel executivo com "cubos" dinâmicos (Bento Box) que se embaralham a
 * cada visita e exibem dados reais das APIs /api/v1/findings,
 * /api/v1/assets/summary e /api/v1/findings/stats/summary.
 */

import React, { useState, useEffect, useRef } from 'react';
import {
  Shield, AlertTriangle, Server, Zap, Activity,
  Eye, GitBranch, Cloud, Flame, Package, Globe, RefreshCw
} from 'lucide-react';

const API = '/api/v1';

// ── Helpers ────────────────────────────────────────────────────────────────────

function shuffle(arr) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function getScoreColor(score) {
  if (score >= 85) return { text: 'text-emerald-400', bar: 'bg-emerald-500', label: 'Excelente' };
  if (score >= 65) return { text: 'text-amber-400',   bar: 'bg-amber-500',   label: 'Moderado'  };
  return              { text: 'text-rose-400',         bar: 'bg-rose-500',    label: 'Crítico'   };
}

function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'short' });
}

function Skeleton({ className = '' }) {
  return <div className={`animate-pulse bg-white/5 rounded-lg ${className}`} />;
}

// ════════════════════════════════════════════════════════════════════════════
//  CUBOS
// ════════════════════════════════════════════════════════════════════════════

function CubeHealthScore({ score, loading, span }) {
  const sc = getScoreColor(score ?? 100);
  return (
    <div className={`${span} relative flex flex-col justify-between p-6 rounded-2xl border border-white/[0.07] bg-gradient-to-br from-[#0d1421]/90 to-[#060b13] overflow-hidden group hover:border-emerald-500/20 transition-all duration-300`}>
      <div className="absolute -top-10 -right-10 w-40 h-40 rounded-full bg-emerald-500/5 blur-3xl group-hover:bg-emerald-500/10 transition-all" />
      <div className="flex items-center justify-between z-10">
        <div className="flex items-center gap-2 text-gray-500">
          <Shield className="w-4 h-4 text-emerald-400/60" />
          <span className="text-[10px] uppercase tracking-widest font-bold">Health Score</span>
        </div>
        <span className="text-[10px] px-2 py-0.5 rounded-full border border-emerald-500/20 bg-emerald-500/5 text-emerald-400/60 font-semibold">Risco Global</span>
      </div>
      <div className="z-10 mt-4">
        {loading
          ? <Skeleton className="w-28 h-14 mb-2" />
          : <div className={`text-6xl font-black ${sc.text} drop-shadow-[0_0_20px_rgba(52,211,153,0.15)]`}>{score ?? 100}</div>
        }
        <div className="flex items-center gap-2 mt-2">
          <div className="flex-1 h-1.5 rounded-full bg-white/5 overflow-hidden">
            <div className={`h-full rounded-full transition-all duration-1000 ${sc.bar}`} style={{ width: `${score ?? 100}%` }} />
          </div>
          <span className={`text-xs font-bold ${sc.text}`}>{sc.label}</span>
        </div>
        <p className="text-[11px] text-gray-600 mt-2">Score calculado sobre postura de segurança global</p>
      </div>
    </div>
  );
}

function CubeCriticalFinding({ finding, loading, span }) {
  return (
    <div className={`${span} relative flex flex-col justify-between p-6 rounded-2xl border border-rose-500/15 bg-gradient-to-br from-[#1a0a0a]/90 to-[#060b13] overflow-hidden group hover:border-rose-500/30 transition-all duration-300`}>
      <div className="absolute -bottom-8 -right-8 w-36 h-36 rounded-full bg-rose-500/5 blur-3xl group-hover:bg-rose-500/10 transition-all" />
      <div className="flex items-center gap-2 text-rose-500/70 z-10">
        <Flame className="w-4 h-4" />
        <span className="text-[10px] uppercase tracking-widest font-bold">Ameaça Ativa</span>
      </div>
      <div className="z-10 mt-3">
        {loading
          ? <><Skeleton className="w-full h-4 mb-2" /><Skeleton className="w-3/4 h-4 mb-3" /><Skeleton className="w-20 h-6" /></>
          : finding
          ? (
            <>
              <p className="text-sm font-bold text-white leading-snug line-clamp-2 mb-2">{finding.title}</p>
              <p className="text-[11px] text-gray-500 line-clamp-2 mb-3">{finding.description || 'Sem descrição disponível.'}</p>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full border bg-rose-500/10 text-rose-400 border-rose-500/25">{finding.severity}</span>
                {finding.asset_id && <span className="text-[10px] text-gray-600 truncate">{finding.asset_id}</span>}
              </div>
            </>
          )
          : <p className="text-sm text-gray-600">Nenhuma ameaça ativa encontrada.</p>
        }
      </div>
    </div>
  );
}

function CubeAssets({ assetsSummary, loading, span }) {
  const items = [
    { label: 'Repositórios', count: assetsSummary?.by_type?.REPOSITORY?.count ?? 0, icon: <GitBranch className="w-3.5 h-3.5 text-purple-400" /> },
    { label: 'Cloud',        count: assetsSummary?.by_type?.CLOUD?.count ?? 0,       icon: <Cloud className="w-3.5 h-3.5 text-sky-400" />     },
    { label: 'Contêineres', count: assetsSummary?.by_type?.CONTAINER?.count ?? 0,   icon: <Package className="w-3.5 h-3.5 text-cyan-400" />   },
    { label: 'Web / API',    count: assetsSummary?.by_type?.DOMAIN?.count ?? 0,     icon: <Globe className="w-3.5 h-3.5 text-emerald-400" />  },
  ];
  return (
    <div className={`${span} relative flex flex-col p-6 rounded-2xl border border-sky-500/10 bg-gradient-to-br from-[#080f1a]/90 to-[#060b13] group hover:border-sky-500/20 transition-all duration-300`}>
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2 text-sky-400/70">
          <Server className="w-4 h-4" />
          <span className="text-[10px] uppercase tracking-widest font-bold">Inventário</span>
        </div>
        {!loading && <span className="text-[10px] text-gray-500 font-bold">{assetsSummary?.total ?? 0} ativos</span>}
      </div>
      <div className="grid grid-cols-2 gap-2 flex-1">
        {loading
          ? Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-10" />)
          : items.map(item => (
            <div key={item.label} className="flex items-center gap-2 bg-white/[0.03] rounded-xl p-2.5 border border-white/[0.05]">
              {item.icon}
              <div><p className="text-xs font-black text-white">{item.count}</p><p className="text-[9px] text-gray-600 leading-tight">{item.label}</p></div>
            </div>
          ))
        }
      </div>
    </div>
  );
}

function CubeSeverity({ counts, loading, span }) {
  const items = [
    { label: 'Crítico', key: 'CRITICAL', color: 'text-rose-400',   bg: 'bg-rose-500/10',   border: 'border-rose-500/15',   bar: 'bg-rose-500/60'   },
    { label: 'Alto',    key: 'HIGH',     color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/15', bar: 'bg-orange-500/60' },
    { label: 'Médio',   key: 'MEDIUM',   color: 'text-amber-400',  bg: 'bg-amber-500/10',  border: 'border-amber-500/15',  bar: 'bg-amber-500/60'  },
    { label: 'Baixo',   key: 'LOW',      color: 'text-blue-400',   bg: 'bg-blue-500/10',   border: 'border-blue-500/15',   bar: 'bg-blue-500/60'   },
  ];
  return (
    <div className={`${span} relative flex flex-col p-6 rounded-2xl border border-white/[0.07] bg-gradient-to-br from-[#0d1421]/90 to-[#060b13] group hover:border-white/10 transition-all duration-300`}>
      <div className="flex items-center gap-2 text-gray-500 mb-4">
        <AlertTriangle className="w-4 h-4 text-amber-400/60" />
        <span className="text-[10px] uppercase tracking-widest font-bold">Findings por Severidade</span>
      </div>
      <div className="flex flex-col gap-2 flex-1">
        {loading
          ? Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-8" />)
          : items.map(item => {
            const val = counts?.[item.key] ?? 0;
            const max = Math.max(counts?.CRITICAL ?? 1, counts?.HIGH ?? 1, counts?.MEDIUM ?? 1, counts?.LOW ?? 1, 1);
            return (
              <div key={item.key} className={`flex items-center gap-3 p-2.5 rounded-xl border ${item.bg} ${item.border}`}>
                <span className={`text-sm font-black w-8 text-right shrink-0 ${item.color}`}>{val}</span>
                <div className="flex-1 h-1 rounded-full bg-white/5 overflow-hidden">
                  <div className={`h-full rounded-full ${item.bar}`} style={{ width: `${(val / max) * 100}%` }} />
                </div>
                <span className={`text-[10px] font-semibold ${item.color} w-12 shrink-0`}>{item.label}</span>
              </div>
            );
          })
        }
      </div>
    </div>
  );
}

function CubeActivity({ findings, loading, span }) {
  const recent = findings?.slice(0, 4) ?? [];
  return (
    <div className={`${span} relative flex flex-col p-6 rounded-2xl border border-purple-500/10 bg-gradient-to-br from-[#0b0d1a]/90 to-[#060b13] group hover:border-purple-500/20 transition-all duration-300`}>
      <div className="flex items-center gap-2 text-purple-400/70 mb-4">
        <Activity className="w-4 h-4" />
        <span className="text-[10px] uppercase tracking-widest font-bold">Atividade Recente</span>
      </div>
      <div className="flex flex-col gap-2 flex-1 overflow-hidden">
        {loading
          ? Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-8" />)
          : recent.length === 0
          ? <p className="text-xs text-gray-600 my-auto text-center">Nenhum finding registrado.</p>
          : recent.map((f, i) => (
            <div key={i} className="flex items-center gap-2.5 py-1.5 border-b border-white/[0.04] last:border-0">
              <span className={`shrink-0 w-1.5 h-1.5 rounded-full ${f.severity === 'CRITICAL' ? 'bg-rose-500' : f.severity === 'HIGH' ? 'bg-orange-500' : f.severity === 'MEDIUM' ? 'bg-amber-500' : 'bg-blue-500'}`} />
              <p className="text-[11px] text-gray-300 font-medium truncate flex-1">{f.title}</p>
              <p className="text-[10px] text-gray-600 shrink-0">{fmtDate(f.created_at)}</p>
            </div>
          ))
        }
      </div>
    </div>
  );
}

const AI_TIPS = [
  { tip: 'Ative o SAST no pipeline CI/CD para bloquear vulnerabilidades antes do merge.', icon: '🔒' },
  { tip: 'Rotacione secrets automaticamente a cada 90 dias com Vault ou AWS Secrets Manager.', icon: '🔑' },
  { tip: 'Aplique o princípio do menor privilégio em todas as roles IAM de Cloud.', icon: '☁️' },
  { tip: 'Containerize workloads e ative image scanning no registry para detectar CVEs.', icon: '📦' },
  { tip: 'Habilite MFA para todos os acessos administrativos. Reduz 99% dos ataques de credencial.', icon: '🛡️' },
  { tip: 'Monitore mudanças de IAC em tempo real — falhas de configuração são a causa nº 1 de breaches cloud.', icon: '⚡' },
];

function CubeAITip({ span }) {
  const [tip] = useState(() => AI_TIPS[Math.floor(Math.random() * AI_TIPS.length)]);
  return (
    <div className={`${span} relative flex flex-col justify-between p-6 rounded-2xl border border-violet-500/15 bg-gradient-to-br from-[#0e0a1a]/90 to-[#060b13] overflow-hidden group hover:border-violet-500/30 transition-all duration-300`}>
      <div className="absolute -top-6 -right-6 w-32 h-32 rounded-full bg-violet-500/5 blur-3xl group-hover:bg-violet-500/10 transition-all" />
      <div className="flex items-center gap-2 text-violet-400/70 z-10">
        <Zap className="w-4 h-4" />
        <span className="text-[10px] uppercase tracking-widest font-bold">IA Security Tip</span>
      </div>
      <div className="z-10 mt-3">
        <p className="text-2xl mb-2">{tip.icon}</p>
        <p className="text-sm text-gray-300 leading-relaxed font-medium">{tip.tip}</p>
      </div>
      <span className="text-[10px] text-violet-500/50 font-semibold z-10 mt-3">Copiloto de Segurança PreviSwit</span>
    </div>
  );
}

function CubePlatformStatus({ loading, totalFindings, totalAssets, span }) {
  return (
    <div className={`${span} relative flex flex-col p-6 rounded-2xl border border-teal-500/10 bg-gradient-to-br from-[#060f10]/90 to-[#060b13] group hover:border-teal-500/20 transition-all duration-300`}>
      <div className="flex items-center gap-2 text-teal-400/70 mb-5">
        <Eye className="w-4 h-4" />
        <span className="text-[10px] uppercase tracking-widest font-bold">Status da Plataforma</span>
      </div>
      <div className="flex flex-col gap-4">
        {loading
          ? Array.from({ length: 2 }).map((_, i) => <Skeleton key={i} className="h-10" />)
          : (
            <>
              <div><p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Total de Findings</p><p className="text-3xl font-black text-orange-400">{totalFindings ?? '—'}</p></div>
              <div><p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Ativos Mapeados</p><p className="text-3xl font-black text-sky-400">{totalAssets ?? '—'}</p></div>
            </>
          )
        }
      </div>
      <div className="mt-auto pt-4 flex items-center gap-1.5">
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
        <span className="text-[10px] text-emerald-500/70 font-semibold">API Backend Online</span>
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
//  BENTO LAYOUT — [cubeId, tailwind span classes]
// ════════════════════════════════════════════════════════════════════════════

const BENTO_LAYOUT = [
  ['health',    'md:col-span-2 md:row-span-2'],
  ['activity',  'md:col-span-2 md:row-span-2'],
  ['severity',  'md:col-span-1 md:row-span-2'],
  ['critical',  'md:col-span-2 md:row-span-1'],
  ['assets',    'md:col-span-1 md:row-span-2'],
  ['status',    'md:col-span-1 md:row-span-1'],
  ['ai',        'md:col-span-2 md:row-span-1'],
];

// ════════════════════════════════════════════════════════════════════════════
//  PAGE
// ════════════════════════════════════════════════════════════════════════════

export default function DashboardPage() {
  const [loading, setLoading]           = useState(true);
  const [findings, setFindings]         = useState([]);
  const [counts, setCounts]             = useState(null);
  const [assetsSummary, setAssets]      = useState(null);
  const [score, setScore]               = useState(null);
  const [cubeOrder, setCubeOrder]       = useState(() => shuffle(BENTO_LAYOUT));
  const isMounted = useRef(true);

  const fetchAll = async () => {
    setLoading(true);
    try {
      const [findRes, statsRes, assetsRes] = await Promise.allSettled([
        fetch(`${API}/findings/?page_size=10`),
        fetch(`${API}/findings/stats/summary`),
        fetch(`${API}/assets/summary`),
      ]);

      if (findRes.status === 'fulfilled' && findRes.value.ok) {
        const d = await findRes.value.json();
        if (isMounted.current) setFindings(d.findings ?? []);
      }
      if (statsRes.status === 'fulfilled' && statsRes.value.ok) {
        const d = await statsRes.value.json();
        if (isMounted.current) {
          const c = d.by_severity ?? d.counts ?? {};
          setCounts(c);
          const s = Math.max(0, 100 - (c.CRITICAL ?? 0) * 15 - (c.HIGH ?? 0) * 5 - (c.MEDIUM ?? 0) * 2);
          setScore(s);
        }
      }
      if (assetsRes.status === 'fulfilled' && assetsRes.value.ok) {
        const d = await assetsRes.value.json();
        if (isMounted.current) setAssets(d);
      }
    } catch (_) {}
    if (isMounted.current) setLoading(false);
  };

  useEffect(() => {
    isMounted.current = true;
    setCubeOrder(shuffle(BENTO_LAYOUT));
    fetchAll();
    return () => { isMounted.current = false; };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const criticalFinding = findings.find(f => f.severity === 'CRITICAL')
    || findings.find(f => f.severity === 'HIGH')
    || findings[0]
    || null;

  const totalFindings =
    (counts?.CRITICAL ?? 0) + (counts?.HIGH ?? 0) +
    (counts?.MEDIUM ?? 0)   + (counts?.LOW ?? 0);

  const renderCube = ([cubeId, span]) => {
    switch (cubeId) {
      case 'health':   return <CubeHealthScore    key={cubeId} score={score}            loading={loading} span={span} />;
      case 'critical': return <CubeCriticalFinding key={cubeId} finding={criticalFinding} loading={loading} span={span} />;
      case 'assets':   return <CubeAssets         key={cubeId} assetsSummary={assetsSummary} loading={loading} span={span} />;
      case 'severity': return <CubeSeverity       key={cubeId} counts={counts}          loading={loading} span={span} />;
      case 'activity': return <CubeActivity       key={cubeId} findings={findings}      loading={loading} span={span} />;
      case 'ai':       return <CubeAITip          key={cubeId}                                            span={span} />;
      case 'status':   return <CubePlatformStatus key={cubeId} totalFindings={totalFindings} totalAssets={assetsSummary?.total} loading={loading} span={span} />;
      default:         return null;
    }
  };

  const nowStr = new Date().toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'short' });

  return (
    <div className="flex flex-col gap-6 w-full pb-10">

      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2.5">
            <Activity className="w-5 h-5 text-blue-400" />
            Visão Geral
          </h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Cockpit Executivo · Bento Dashboard · Atualizado {nowStr}
          </p>
        </div>
        <button
          onClick={() => { setCubeOrder(shuffle(BENTO_LAYOUT)); fetchAll(); }}
          className="flex items-center gap-1.5 text-xs bg-white/[0.04] hover:bg-white/[0.08] text-gray-400 hover:text-white border border-white/[0.08] px-3 py-1.5 rounded-lg transition-all"
        >
          <RefreshCw className="w-3 h-3" />
          Embaralhar &amp; Atualizar
        </button>
      </div>

      {/* Bento Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 auto-rows-[180px] gap-4">
        {cubeOrder.map(renderCube)}
      </div>

    </div>
  );
}

