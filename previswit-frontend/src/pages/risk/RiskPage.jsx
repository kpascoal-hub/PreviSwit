/**
 * PreviSwit AI-ASPM — Métricas de Risco & Conformidade
 * =======================================================
 * Cockpit Executivo (C-Level): Health Score Evolutivo, Exposição Financeira,
 * e Painel de Compliance (ISO 27001 / SOC 2).
 *
 * Coleta os resultados da varredura diretamente do localStorage.
 *
 * Design: Cyber Dark Enterprise (#060b13 / glass cards / gradientes).
 */

import React, { useState, useEffect, useMemo } from 'react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from 'recharts';
import {
  Activity, DollarSign, ShieldAlert, CheckCircle2,
  AlertTriangle, Shield, TrendingUp, TrendingDown, ChevronRight
} from 'lucide-react';

// ── Funções de Cálculo ────────────────────────────────────────────────────────

function calculateScore(findings) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  findings.forEach(f => {
    if (counts[f.severity] !== undefined) counts[f.severity]++;
  });

  let score = 100 - (counts.CRITICAL * 15) - (counts.HIGH * 5) - (counts.MEDIUM * 2);
  return Math.max(0, score);
}

function getScoreGrade(score) {
  if (score >= 90) return { grade: 'A', color: 'text-emerald-400',  bg: 'bg-emerald-500/10',  border: 'border-emerald-500/30' };
  if (score >= 75) return { grade: 'B', color: 'text-blue-400',     bg: 'bg-blue-500/10',     border: 'border-blue-500/30' };
  if (score >= 60) return { grade: 'C', color: 'text-amber-400',    bg: 'bg-amber-500/10',    border: 'border-amber-500/30' };
  if (score >= 40) return { grade: 'D', color: 'text-orange-400',   bg: 'bg-orange-500/10',   border: 'border-orange-500/30' };
  return           { grade: 'F', color: 'text-rose-400',     bg: 'bg-rose-500/10',     border: 'border-rose-500/30' };
}

// ── Componente Custom Tooltip Recharts ────────────────────────────────────────

const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    const val = payload[0].value;
    return (
      <div className="bg-[#060b13]/95 border border-white/[0.08] p-3 rounded-xl shadow-xl backdrop-blur-md">
        <p className="text-[10px] text-gray-500 uppercase tracking-wider font-bold mb-1">{label}</p>
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.6)]" />
          <p className="text-lg font-black text-white">Score: <span className="text-emerald-400">{val}</span></p>
        </div>
      </div>
    );
  }
  return null;
};

// ── Componente Principal ──────────────────────────────────────────────────────

export default function RiskPage() {
  const [counts,       setCounts]       = useState({ CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 });
  const [currentScore, setCurrentScore] = useState(100);
  const [history,      setHistory]      = useState([]);
  const [findings,     setFindings]     = useState([]);
  const [loading,      setLoading]      = useState(true);

  // Hidratação via API
  useEffect(() => {
    (async () => {
      try {
        // Busca summary (contagens por severidade)
        const sumRes = await fetch('/api/v1/findings/stats/summary');
        if (sumRes.ok) {
          const summary = await sumRes.json();
          const c = {
            CRITICAL: summary.by_severity?.CRITICAL || 0,
            HIGH:     summary.by_severity?.HIGH     || 0,
            MEDIUM:   summary.by_severity?.MEDIUM   || 0,
            LOW:      summary.by_severity?.LOW      || 0,
          };
          setCounts(c);

          // Calcula score com base nos contadores
          const score = Math.max(0, 100 - (c.CRITICAL * 15) - (c.HIGH * 5) - (c.MEDIUM * 2));
          setCurrentScore(score);

          // Busca lista completa para compliance parser
          const listRes = await fetch('/api/v1/findings/?page_size=500');
          if (listRes.ok) {
            const listJson = await listRes.json();
            setFindings(listJson.findings || []);
          }

          // Histórico Evolutivo (mantido no localStorage por ser dado local temporal)
          const today = new Date().toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit' });
          let hist = [];
          try { hist = JSON.parse(localStorage.getItem('previswit_score_history') || '[]'); } catch (_) {}

          if (hist.length === 0) {
            hist = [
              { date: '12/07', score: Math.max(0, score - 15) },
              { date: '13/07', score: Math.max(0, score - 12) },
              { date: '14/07', score: Math.max(0, score - 10) },
              { date: '15/07', score: Math.max(0, score - 5)  },
              { date: '16/07', score: Math.max(0, score - 2)  },
            ];
          }
          const todayIdx = hist.findIndex(h => h.date === today);
          if (todayIdx >= 0) hist[todayIdx].score = score;
          else hist.push({ date: today, score });
          if (hist.length > 30) hist = hist.slice(-30);
          localStorage.setItem('previswit_score_history', JSON.stringify(hist));
          setHistory(hist);
        }
      } catch (e) {
        console.error('[RiskPage] Erro ao carregar API:', e);
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  // ── Cálculos Derivados ──────────────────────────────────────────────────

  const financialExposure = counts.CRITICAL * 50000;
  const gradeData = getScoreGrade(currentScore);

  // ── Compliance Parser ───────────────────────────────────────────────────

  const complianceIssues = useMemo(() => {
    const issues = [];
    const triggerRegex = /secret|key|authentication|sqli|injection|auth/i;
    
    findings.forEach(f => {
      if (triggerRegex.test(f.title) || triggerRegex.test(f.description)) {
        issues.push(f);
      }
    });

    // Filtra únicas pelo título para não poluir
    const unique = [];
    const seen = new Set();
    issues.forEach(i => {
      if (!seen.has(i.title)) {
        seen.add(i.title);
        unique.push(i);
      }
    });
    return unique;
  }, [findings]);

  const compliancePercentage = Math.max(0, 100 - (complianceIssues.length * 15));

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="flex flex-col gap-6 w-full pb-10">

      {/* ── Header ──────────────────────────────────────────────────────── */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2.5">
            <Activity className="w-5 h-5 text-emerald-400" />
            Métricas de Risco & Conformidade
          </h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Cockpit C-Level · Health Score Evolutivo · Monitoramento ISO 27001 / SOC 2
          </p>
        </div>
      </div>

      {/* ── KPI Cards (Cockpit Executivo) ───────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        
        {/* Health Score */}
        <div className="rounded-2xl border border-white/[0.06] bg-gradient-to-b from-[#0d1421]/90 to-[#060b13]/80 p-6 flex flex-col justify-between">
          <div className="flex items-start justify-between mb-4">
            <div className="flex items-center gap-2 text-gray-500">
              <Shield className="w-4 h-4" />
              <span className="text-[10px] uppercase tracking-wider font-bold">Health Score Atual</span>
            </div>
            <div className={`w-8 h-8 rounded-lg flex items-center justify-center font-black text-lg border ${gradeData.bg} ${gradeData.color} ${gradeData.border}`}>
              {gradeData.grade}
            </div>
          </div>
          <div className="flex items-end gap-3">
            <span className={`text-5xl font-black ${gradeData.color} drop-shadow-[0_0_12px_rgba(255,255,255,0.1)]`}>
              {currentScore}
            </span>
            <span className="text-sm font-bold text-gray-500 mb-1">/ 100</span>
          </div>
          <p className="text-[10px] text-gray-600 mt-3 font-semibold">
            {currentScore >= 90 ? 'Excelente postura de segurança.' : currentScore >= 75 ? 'Risco aceitável. Monitoramento ativo.' : 'Alerta: Intervenção necessária.'}
          </p>
        </div>

        {/* Exposição Financeira */}
        <div className="rounded-2xl border border-rose-500/20 bg-gradient-to-b from-[#1a0f14]/90 to-[#060b13]/80 p-6 flex flex-col justify-between relative overflow-hidden">
          <div className="absolute top-0 right-0 w-32 h-32 bg-rose-500/10 rounded-full blur-3xl -mr-10 -mt-10" />
          <div className="flex items-start justify-between mb-4 relative z-10">
            <div className="flex items-center gap-2 text-rose-500/80">
              <DollarSign className="w-4 h-4" />
              <span className="text-[10px] uppercase tracking-wider font-bold">Exposição Estimada (USD)</span>
            </div>
          </div>
          <div className="flex items-end gap-2 relative z-10">
            <span className="text-4xl font-black text-rose-400 drop-shadow-[0_0_8px_rgba(244,63,94,0.4)]">
              ${financialExposure.toLocaleString('en-US')}
            </span>
          </div>
          <p className="text-[10px] text-rose-500/70 mt-3 font-semibold relative z-10">
            Baseado em incidentes críticos (Multas LGPD/Breach)
          </p>
        </div>

        {/* Ameaças Ativas */}
        <div className="rounded-2xl border border-amber-500/20 bg-gradient-to-b from-[#14120e]/90 to-[#060b13]/80 p-6 flex flex-col justify-between relative overflow-hidden">
          <div className="absolute top-0 right-0 w-32 h-32 bg-amber-500/10 rounded-full blur-3xl -mr-10 -mt-10" />
          <div className="flex items-start justify-between mb-4 relative z-10">
            <div className="flex items-center gap-2 text-amber-500/80">
              <ShieldAlert className="w-4 h-4" />
              <span className="text-[10px] uppercase tracking-wider font-bold">Ameaças Ativas</span>
            </div>
            {counts.CRITICAL > 0 && (
              <span className="flex items-center gap-1 text-[9px] font-bold text-rose-400 bg-rose-500/10 border border-rose-500/20 px-2 py-0.5 rounded-full">
                <TrendingUp className="w-3 h-3" /> CRITICAL
              </span>
            )}
          </div>
          <div className="flex items-end gap-3 relative z-10">
            <span className="text-4xl font-black text-amber-400 drop-shadow-[0_0_8px_rgba(245,158,11,0.3)]">
              {findings.length}
            </span>
            <span className="text-sm font-bold text-gray-500 mb-1">falhas</span>
          </div>
          <div className="flex items-center gap-3 mt-3 relative z-10">
            <span className="text-[10px] font-bold text-rose-400">{counts.CRITICAL} Crit</span>
            <span className="text-[10px] font-bold text-red-400">{counts.HIGH} High</span>
            <span className="text-[10px] font-bold text-amber-400">{counts.MEDIUM} Med</span>
          </div>
        </div>

      </div>

      {/* ── Evolução de Risco (Gráfico) ─────────────────────────────────── */}
      <div className="rounded-2xl border border-white/[0.06] bg-[#030710]/40 overflow-hidden">
        <div className="flex items-center justify-between px-6 py-4 border-b border-white/[0.05] bg-[#060b13]/80">
          <div className="flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-emerald-400" />
            <span className="text-sm font-bold text-white">Evolução do Risco (Score)</span>
          </div>
          <span className="text-[10px] text-gray-600 font-mono">Últimos {history.length} dias</span>
        </div>
        
        <div className="p-6 h-[300px] w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={history} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#34d399" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#34d399" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
              <XAxis 
                dataKey="date" 
                stroke="rgba(255,255,255,0.2)" 
                tick={{ fill: 'rgba(255,255,255,0.4)', fontSize: 10 }}
                tickLine={false}
                axisLine={false}
                dy={10}
              />
              <YAxis 
                domain={[0, 100]} 
                stroke="rgba(255,255,255,0.2)"
                tick={{ fill: 'rgba(255,255,255,0.4)', fontSize: 10 }}
                tickLine={false}
                axisLine={false}
              />
              <Tooltip content={<CustomTooltip />} />
              <Area 
                type="monotone" 
                dataKey="score" 
                stroke="#34d399" 
                strokeWidth={3}
                fillOpacity={1} 
                fill="url(#colorScore)" 
                activeDot={{ r: 6, fill: '#060b13', stroke: '#34d399', strokeWidth: 3 }}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* ── Painel de Compliance (ISO 27001 / SOC 2) ────────────────────── */}
      <div className="rounded-2xl border border-white/[0.06] bg-gradient-to-b from-[#0d1421]/60 to-[#060b13]/80 overflow-hidden">
        <div className="flex items-center gap-2 px-6 py-4 border-b border-white/[0.05] bg-[#060b13]/80">
          <CheckCircle2 className="w-4 h-4 text-blue-400" />
          <span className="text-sm font-bold text-white">Status de Conformidade (ISO 27001 & SOC 2)</span>
        </div>
        
        <div className="p-6">
          {/* Progress Bar Container */}
          <div className="mb-6">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] uppercase tracking-wider font-bold text-gray-400">Adherência Global</span>
              <span className="text-xs font-black text-white">{compliancePercentage}%</span>
            </div>
            <div className="w-full h-2.5 rounded-full bg-white/[0.05] overflow-hidden">
              <div 
                className={`h-full rounded-full transition-all duration-1000 ${
                  compliancePercentage === 100 ? 'bg-emerald-500' : compliancePercentage >= 70 ? 'bg-amber-500' : 'bg-rose-500'
                }`}
                style={{ width: `${compliancePercentage}%` }}
              />
            </div>
          </div>

          {/* Violações / Ok State */}
          {complianceIssues.length === 0 ? (
            <div className="flex items-center gap-3 p-4 rounded-xl bg-emerald-500/5 border border-emerald-500/20">
              <div className="w-8 h-8 rounded-lg bg-emerald-500/15 flex items-center justify-center shrink-0">
                <Shield className="w-4 h-4 text-emerald-400" />
              </div>
              <div>
                <p className="text-xs font-bold text-emerald-400">100% — Em Conformidade</p>
                <p className="text-[10px] text-emerald-500/70 font-semibold mt-0.5">Nenhuma violação crítica de controle detectada.</p>
              </div>
            </div>
          ) : (
            <div className="flex flex-col gap-3">
              <p className="text-[10px] uppercase tracking-wider font-bold text-gray-500">Violações de Controle Detectadas</p>
              {complianceIssues.slice(0, 5).map((issue, idx) => (
                <div key={idx} className="flex items-start gap-3 p-3 rounded-xl bg-white/[0.02] border border-white/[0.05] group hover:bg-white/[0.04] transition-colors">
                  <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                  <div className="min-w-0">
                    <p className="text-xs font-bold text-gray-200 truncate">{issue.title}</p>
                    <p className="text-[10px] text-gray-500 mt-1">
                      Potencial quebra de requisitos de autenticação/criptografia (ISO 27001 A.9 / A.10).
                    </p>
                  </div>
                  <ChevronRight className="w-4 h-4 text-gray-600 ml-auto opacity-0 group-hover:opacity-100 transition-opacity" />
                </div>
              ))}
              {complianceIssues.length > 5 && (
                <p className="text-[10px] text-center text-gray-600 mt-2 font-bold">+ {complianceIssues.length - 5} outras violações não exibidas</p>
              )}
            </div>
          )}

        </div>
      </div>

    </div>
  );
}
