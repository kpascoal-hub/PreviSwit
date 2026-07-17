/**
 * PreviSwit AI-ASPM — Central de Findings
 * =========================================
 * Single Pane of Glass para triagem de vulnerabilidades.
 *
 * Coleta automática do localStorage:
 *   previswit_scan_*       → SAST (Semgrep / Gitleaks)
 *   previswit_iac_*        → Cloud / IaC (Checkov)
 *   previswit_container_*  → Containers (Trivy)
 *   previswit_pentest_*    → DAST / Pentest (IA Active Attacker)
 *   previswit_dast_*       → DAST (ataque de superfície)
 *
 * Motor de Deduplicação:
 *   Agrupa por título normalizado + CVE.
 *   Funde duplicatas em um único objeto com occurrences + scanners[].
 *
 * Design: Cyber Dark Enterprise — sem bibliotecas externas, 100% performático.
 */

import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  ShieldAlert, AlertTriangle, ChevronRight, RefreshCw,
  Filter, Layers, Shield, Code, Globe, Package,
  CheckCircle2, Clock, XCircle, Cpu,
} from 'lucide-react';

// ── Constantes de coleta de localStorage ─────────────────────────────────────

const LS_PREFIXES = [
  { prefix: 'previswit_scan_',      source: 'Code',      label: 'SAST / Secrets',    icon: Code },
  { prefix: 'previswit_iac_',       source: 'Cloud',     label: 'Cloud / IaC',       icon: Shield },
  { prefix: 'previswit_container_', source: 'Container', label: 'Containers (Trivy)', icon: Package },
  { prefix: 'previswit_pentest_',   source: 'DAST',      label: 'Pentest (DAST)',    icon: Globe },
  { prefix: 'previswit_dast_',      source: 'DAST',      label: 'DAST / Superfície', icon: Globe },
];

// ── Helpers de severidade ─────────────────────────────────────────────────────

function normSev(raw) {
  const s = (raw || '').toUpperCase().trim();
  if (s === 'CRITICAL' || s === 'CRÍTICO')                return 'CRITICAL';
  if (s === 'HIGH'     || s === 'ALTO'   || s === 'ERROR') return 'HIGH';
  if (s === 'MEDIUM'   || s === 'MÉDIO'  || s === 'WARN')  return 'MEDIUM';
  if (s === 'LOW'      || s === 'BAIXO'  || s === 'INFO')  return 'LOW';
  return 'INFO';
}

function sevColors(sev) {
  switch (sev) {
    case 'CRITICAL': return { bg: 'bg-rose-500/10',   text: 'text-rose-400',   border: 'border-rose-500/25',   dot: 'bg-rose-500',   glow: 'drop-shadow-[0_0_8px_rgba(244,63,94,0.5)]' };
    case 'HIGH':     return { bg: 'bg-red-500/10',    text: 'text-red-400',    border: 'border-red-500/25',    dot: 'bg-red-500',    glow: 'drop-shadow-[0_0_8px_rgba(239,68,68,0.5)]' };
    case 'MEDIUM':   return { bg: 'bg-amber-500/10',  text: 'text-amber-400',  border: 'border-amber-500/25',  dot: 'bg-amber-500',  glow: 'drop-shadow-[0_0_6px_rgba(245,158,11,0.4)]' };
    case 'LOW':      return { bg: 'bg-blue-500/10',   text: 'text-blue-400',   border: 'border-blue-500/25',   dot: 'bg-blue-500',   glow: '' };
    default:         return { bg: 'bg-gray-500/10',   text: 'text-gray-400',   border: 'border-gray-500/25',   dot: 'bg-gray-500',   glow: '' };
  }
}

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

const SOURCE_COLORS = {
  Code:      { bg: 'bg-violet-500/10',  text: 'text-violet-400',  border: 'border-violet-500/25' },
  Cloud:     { bg: 'bg-cyan-500/10',    text: 'text-cyan-400',    border: 'border-cyan-500/25' },
  Container: { bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/25' },
  DAST:      { bg: 'bg-rose-500/10',    text: 'text-rose-400',    border: 'border-rose-500/25' },
};

// ── Extractor: normaliza findings de qualquer formato de laudo ───────────────

function extractFindings(lsData, source, targetKey) {
  if (!lsData || typeof lsData !== 'object') return [];

  // Suporta múltiplos formatos de chave de resultados
  const arr =
    lsData.findings_prioritized ||
    lsData.findings             ||
    lsData.vulnerabilities      ||
    lsData.results              ||
    lsData.checks               ||
    [];

  if (!Array.isArray(arr)) return [];

  return arr.map(f => ({
    // Normaliza campos de título
    title:      f.vulnerability || f.title || f.name || f.check_id || f.rule_id || f.description || '—',
    cve:        f.cve || f.CVE || f.cve_id || '',
    severity:   normSev(f.severity || f.risk || f.level || ''),
    description: f.description || f.detail || f.message || '',
    remediation: f.remediation || f.fix || '',
    reference:  f.reference || f.url || f.link || '',
    endpoint:   f.endpoint || f.url || f.path || f.file_path || '',
    payload:    f.payload || f.ai_payload || f.evidence || '',
    proof:      f.proof_status || f.status || '',
    scanner:    f.tool || f.scanner || source,
    source,
    target:     targetKey,
    raw:        f,
  }));
}

// ── Motor de Deduplicação ─────────────────────────────────────────────────────

function deduplicateFindings(all) {
  const map = new Map();

  all.forEach(f => {
    // Chave de dedup: CVE (se existir) OU título normalizado
    const normTitle = (f.title || '').toLowerCase().replace(/\s+/g, ' ').trim();
    const key = f.cve ? `cve:${f.cve.toUpperCase()}` : `title:${normTitle}`;

    if (map.has(key)) {
      const existing = map.get(key);
      existing.occurrences += 1;
      if (!existing.targets.includes(f.target)) existing.targets.push(f.target);
      if (!existing.scanners.includes(f.scanner)) existing.scanners.push(f.scanner);
      if (!existing.sources.includes(f.source)) existing.sources.push(f.source);
      // Eleva para severidade mais alta se encontrar duplicata mais grave
      if (SEV_ORDER[f.severity] < SEV_ORDER[existing.severity]) {
        existing.severity = f.severity;
      }
      // Acumula descrição extra
      if (f.description && !existing.details.includes(f.description)) {
        existing.details.push(f.description);
      }
    } else {
      map.set(key, {
        key,
        title:       f.title,
        cve:         f.cve,
        severity:    f.severity,
        occurrences: 1,
        targets:     [f.target],
        scanners:    [f.scanner],
        sources:     [f.source],
        details:     f.description ? [f.description] : [],
        remediation: f.remediation,
        reference:   f.reference,
        endpoint:    f.endpoint,
        payload:     f.payload,
        proof:       f.proof,
        raw:         f.raw,
      });
    }
  });

  // Ordena: Critical primeiro, depois occurrences decrescentes
  return Array.from(map.values()).sort((a, b) => {
    const sevDiff = SEV_ORDER[a.severity] - SEV_ORDER[b.severity];
    if (sevDiff !== 0) return sevDiff;
    return b.occurrences - a.occurrences;
  });
}

// ── Coleta global do localStorage ─────────────────────────────────────────────

function collectAllFindings() {
  const raw = [];
  const allKeys = Object.keys(localStorage);

  LS_PREFIXES.forEach(({ prefix, source }) => {
    allKeys
      .filter(k => k.startsWith(prefix))
      .forEach(k => {
        try {
          const data = JSON.parse(localStorage.getItem(k) || '{}');
          const target = k.replace(prefix, '').replace(/_/g, ' ') || k;
          const items = extractFindings(data, source, target);
          raw.push(...items);
        } catch (_) {}
      });
  });

  return raw;
}

// ── Componente: linha expandível ─────────────────────────────────────────────

function FindingRow({ finding, index }) {
  const [expanded, setExpanded] = useState(false);
  const sC = sevColors(finding.severity);

  return (
    <div className="border-b border-white/[0.04] last:border-0 group">
      {/* Main row */}
      <div
        onClick={() => setExpanded(e => !e)}
        className={`grid grid-cols-12 gap-3 items-center px-5 py-3.5 cursor-pointer transition-all duration-150
                    hover:bg-white/[0.025] ${index % 2 === 0 ? 'bg-transparent' : 'bg-white/[0.01]'}`}
      >
        {/* # + expand */}
        <div className="col-span-1 flex items-center gap-2">
          <ChevronRight className={`w-3 h-3 text-gray-600 transition-transform duration-200 shrink-0 ${expanded ? 'rotate-90' : ''}`} />
          <span className="text-[10px] text-gray-600 font-mono">#{String(index + 1).padStart(3, '0')}</span>
        </div>

        {/* Título */}
        <div className="col-span-4 min-w-0">
          <p className="text-xs font-semibold text-gray-200 truncate">{finding.title}</p>
          {finding.cve && (
            <span className="text-[9px] font-mono text-cyan-500">{finding.cve}</span>
          )}
        </div>

        {/* Alvos / Ocorrências */}
        <div className="col-span-2 min-w-0">
          <div className="flex items-center gap-1 flex-wrap">
            {finding.targets.slice(0, 2).map((t, i) => (
              <span key={i} className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-white/[0.04] text-gray-400 truncate max-w-[80px]">{t}</span>
            ))}
            {finding.targets.length > 2 && (
              <span className="text-[9px] text-gray-600">+{finding.targets.length - 2}</span>
            )}
          </div>
          <p className="text-[10px] text-gray-600 mt-0.5">{finding.occurrences}x detectada</p>
        </div>

        {/* Scanners */}
        <div className="col-span-2 flex flex-wrap gap-1">
          {finding.scanners.map((s, i) => {
            const sc = SOURCE_COLORS[finding.sources[i]] || SOURCE_COLORS.Code;
            return (
              <span key={i} className={`text-[9px] px-1.5 py-0.5 rounded-full border font-bold ${sc.bg} ${sc.text} ${sc.border}`}>
                {s}
              </span>
            );
          })}
        </div>

        {/* Severidade */}
        <div className="col-span-2">
          <span className={`inline-flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded-full border ${sC.bg} ${sC.text} ${sC.border}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${sC.dot}`} />
            {finding.severity}
          </span>
        </div>

        {/* Status */}
        <div className="col-span-1 flex justify-end">
          <span className="text-[10px] px-2 py-0.5 rounded-full bg-amber-500/10 border border-amber-500/20 text-amber-400 font-bold">
            Open
          </span>
        </div>
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div className="px-5 py-4 bg-[#030710]/80 border-b border-white/[0.04]">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

            {finding.details.length > 0 && (
              <div className="md:col-span-2">
                <p className="text-[9px] text-gray-600 uppercase tracking-wider font-bold mb-1.5">Evidência / Descrição</p>
                <div className="space-y-1">
                  {finding.details.map((d, i) => (
                    <p key={i} className="text-xs text-gray-300 leading-relaxed bg-black/30 rounded-lg p-2">{d}</p>
                  ))}
                </div>
              </div>
            )}

            {finding.endpoint && (
              <div>
                <p className="text-[9px] text-gray-600 uppercase tracking-wider font-bold mb-1">Endpoint / Arquivo</p>
                <p className="text-xs font-mono text-blue-400 break-all">{finding.endpoint}</p>
              </div>
            )}

            {finding.payload && (
              <div>
                <p className="text-[9px] text-gray-600 uppercase tracking-wider font-bold mb-1">Payload IA</p>
                <pre className="text-[10px] font-mono text-purple-400 bg-black/40 rounded-lg p-2 overflow-x-auto whitespace-pre-wrap break-words max-h-24">{
                  typeof finding.payload === 'string' ? finding.payload : JSON.stringify(finding.payload, null, 2)
                }</pre>
              </div>
            )}

            {finding.remediation && (
              <div className="md:col-span-2">
                <p className="text-[9px] text-gray-600 uppercase tracking-wider font-bold mb-1">Remediação</p>
                <p className="text-xs text-emerald-400 leading-relaxed">{finding.remediation}</p>
              </div>
            )}

            <div>
              <p className="text-[9px] text-gray-600 uppercase tracking-wider font-bold mb-1">Todos os Alvos</p>
              <div className="flex flex-wrap gap-1">
                {finding.targets.map((t, i) => (
                  <span key={i} className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-white/[0.05] text-gray-400">{t}</span>
                ))}
              </div>
            </div>

            {finding.reference && (
              <div>
                <p className="text-[9px] text-gray-600 uppercase tracking-wider font-bold mb-1">Referência</p>
                <a href={finding.reference} target="_blank" rel="noopener noreferrer"
                   className="text-xs text-blue-400 hover:text-blue-300 underline break-all transition-colors">
                  {finding.reference}
                </a>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Componente Principal ──────────────────────────────────────────────────────

export default function FindingsPage() {
  const [allRaw,       setAllRaw]       = useState([]);
  const [sevFilter,    setSevFilter]    = useState('ALL');
  const [sourceFilter, setSourceFilter] = useState('ALL');
  const [lastRefresh,  setLastRefresh]  = useState(null);

  // ── Coleta + deduplicação ─────────────────────────────────────────────────

  const hydrate = useCallback(() => {
    const raw = collectAllFindings();
    setAllRaw(raw);
    setLastRefresh(new Date().toLocaleTimeString('pt-BR', { hour12: false }));
  }, []);

  useEffect(() => { hydrate(); }, [hydrate]);

  // ── Dedup memoizado (não bloqueia a UI) ───────────────────────────────────

  const deduped = useMemo(() => deduplicateFindings(allRaw), [allRaw]);

  // ── Filtro aplicado ───────────────────────────────────────────────────────

  const filtered = useMemo(() => {
    return deduped.filter(f => {
      const sevOk    = sevFilter    === 'ALL' || f.severity === sevFilter;
      const srcOk    = sourceFilter === 'ALL' || f.sources.includes(sourceFilter);
      return sevOk && srcOk;
    });
  }, [deduped, sevFilter, sourceFilter]);

  // ── KPIs ──────────────────────────────────────────────────────────────────

  const kpi = useMemo(() => ({
    total:    deduped.length,
    critical: deduped.filter(f => f.severity === 'CRITICAL').length,
    high:     deduped.filter(f => f.severity === 'HIGH').length,
    medium:   deduped.filter(f => f.severity === 'MEDIUM').length,
    sources:  [...new Set(deduped.flatMap(f => f.sources))].length,
  }), [deduped]);

  const sources = useMemo(() =>
    [...new Set(deduped.flatMap(f => f.sources))].sort(),
  [deduped]);

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="flex flex-col gap-6 w-full">

      {/* ── Header ──────────────────────────────────────────────────────── */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2.5">
            <ShieldAlert className="w-5 h-5 text-rose-400" />
            Central de Findings
          </h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Triagem unificada · Deduplicação automática · Single Pane of Glass
          </p>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          {lastRefresh && (
            <span className="text-[10px] text-gray-600 font-mono">Atualizado: {lastRefresh}</span>
          )}
          <button
            onClick={hydrate}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-white/[0.08] bg-white/[0.03] text-gray-400 hover:text-white hover:bg-white/[0.06] text-[11px] font-bold transition-all"
          >
            <RefreshCw className="w-3.5 h-3.5" /> Reanalisar
          </button>
        </div>
      </div>

      {/* ── KPI Cards ───────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[
          { label: 'Total (Únicos)', value: kpi.total,    color: 'text-white',      border: 'border-white/[0.06]',  glow: '' },
          { label: 'Critical',       value: kpi.critical, color: 'text-rose-400',   border: 'border-rose-500/15',   glow: 'drop-shadow-[0_0_8px_rgba(244,63,94,0.4)]' },
          { label: 'High',           value: kpi.high,     color: 'text-red-400',    border: 'border-red-500/15',    glow: 'drop-shadow-[0_0_8px_rgba(239,68,68,0.4)]' },
          { label: 'Medium',         value: kpi.medium,   color: 'text-amber-400',  border: 'border-amber-500/15',  glow: 'drop-shadow-[0_0_6px_rgba(245,158,11,0.3)]' },
          { label: 'Origens',        value: kpi.sources,  color: 'text-purple-400', border: 'border-purple-500/15', glow: '' },
        ].map(k => (
          <div key={k.label}
               className={`flex items-center justify-between px-4 py-4 rounded-xl bg-gradient-to-b from-[#0d1421]/70 to-[#060b13]/60 border ${k.border}`}>
            <p className="text-[10px] text-gray-600 uppercase tracking-wider font-bold">{k.label}</p>
            <span className={`text-3xl font-black ${k.color} ${k.glow}`}>{k.value}</span>
          </div>
        ))}
      </div>

      {/* ── Filtros ─────────────────────────────────────────────────────── */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex items-center gap-2 text-gray-600">
          <Filter className="w-3.5 h-3.5" />
          <span className="text-[10px] uppercase tracking-wider font-bold">Filtros</span>
        </div>

        {/* Severidade */}
        <div className="flex items-center bg-white/[0.03] border border-white/[0.06] rounded-xl p-1 gap-1">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => {
            const sc = s === 'ALL' ? { text: 'text-gray-300' } : sevColors(s);
            return (
              <button
                key={s}
                onClick={() => setSevFilter(s)}
                className={`px-3 py-1 rounded-lg text-[10px] font-bold transition-all
                           ${sevFilter === s
                             ? `bg-white/[0.08] ${sc.text} shadow-sm`
                             : 'text-gray-600 hover:text-gray-300'}`}
              >
                {s === 'ALL' ? 'Todos' : s}
                {s !== 'ALL' && (
                  <span className="ml-1 text-[9px] opacity-60">
                    ({deduped.filter(f => f.severity === s).length})
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Origem */}
        <div className="flex items-center bg-white/[0.03] border border-white/[0.06] rounded-xl p-1 gap-1">
          {['ALL', ...sources].map(src => {
            const sc = SOURCE_COLORS[src] || {};
            return (
              <button
                key={src}
                onClick={() => setSourceFilter(src)}
                className={`px-3 py-1 rounded-lg text-[10px] font-bold transition-all flex items-center gap-1
                           ${sourceFilter === src
                             ? `bg-white/[0.08] ${sc.text || 'text-gray-300'} shadow-sm`
                             : 'text-gray-600 hover:text-gray-300'}`}
              >
                {src === 'ALL' ? 'Todas as origens' : src}
              </button>
            );
          })}
        </div>

        <span className="ml-auto text-[10px] text-gray-600">
          {filtered.length} finding{filtered.length !== 1 ? 's' : ''} únicos
          {filtered.length !== deduped.length && ` (de ${deduped.length} total)`}
        </span>
      </div>

      {/* ── DataGrid Principal ───────────────────────────────────────────── */}
      <div className="rounded-2xl border border-white/[0.06] bg-gradient-to-b from-[#0d1421]/80 to-[#060b13]/60 overflow-hidden">

        {/* Column headers */}
        <div className="grid grid-cols-12 gap-3 px-5 py-2.5 text-[9px] text-gray-500 uppercase tracking-wider font-bold border-b border-white/[0.05] bg-[#030710]/60">
          <div className="col-span-1" />
          <div className="col-span-4">Vulnerabilidade</div>
          <div className="col-span-2">Alvos Afetados</div>
          <div className="col-span-2">Scanners</div>
          <div className="col-span-2">Severidade</div>
          <div className="col-span-1 text-right">Status</div>
        </div>

        {/* Rows */}
        <div className="max-h-[600px] overflow-y-auto">
          {filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 gap-4">
              {allRaw.length === 0 ? (
                <>
                  <div className="w-14 h-14 rounded-2xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center">
                    <Layers className="w-6 h-6 text-blue-400/50" />
                  </div>
                  <div className="text-center">
                    <p className="text-sm font-semibold text-gray-300">Nenhum laudo encontrado</p>
                    <p className="text-xs text-gray-600 mt-1.5 max-w-sm leading-relaxed">
                      Execute scans nas abas <span className="text-blue-400">SAST</span>,{' '}
                      <span className="text-cyan-400">Cloud</span>,{' '}
                      <span className="text-emerald-400">Containers</span> ou{' '}
                      <span className="text-rose-400">Pentest</span> para que os findings
                      apareçam aqui automaticamente.
                    </p>
                  </div>
                </>
              ) : (
                <>
                  <div className="w-12 h-12 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
                    <Shield className="w-5 h-5 text-emerald-400" />
                  </div>
                  <p className="text-sm font-semibold text-emerald-400">Nenhum finding para os filtros selecionados</p>
                </>
              )}
            </div>
          ) : (
            filtered.map((f, i) => (
              <FindingRow key={f.key} finding={f} index={i} />
            ))
          )}
        </div>

        {/* Footer info */}
        {filtered.length > 0 && (
          <div className="flex items-center justify-between px-5 py-2.5 border-t border-white/[0.04] bg-[#030710]/40">
            <p className="text-[10px] text-gray-600">
              {allRaw.length} vulnerabilidades brutas → {deduped.length} únicas após deduplicação
            </p>
            <div className="flex items-center gap-3">
              {LS_PREFIXES.filter(p =>
                Object.keys(localStorage).some(k => k.startsWith(p.prefix))
              ).map(p => {
                const sc = SOURCE_COLORS[p.source] || {};
                return (
                  <span key={p.prefix} className={`text-[9px] px-2 py-0.5 rounded-full border font-bold ${sc.bg} ${sc.text} ${sc.border}`}>
                    {p.label}
                  </span>
                );
              })}
            </div>
          </div>
        )}
      </div>

    </div>
  );
}
