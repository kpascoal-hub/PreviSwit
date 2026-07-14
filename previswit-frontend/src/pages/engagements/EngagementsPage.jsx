/**
 * PreviSwit AI-ASPM — Pentest & Orquestração de Scans DAST
 * =========================================================
 * Cockpit de ataque centralizado: interface de pentest contínuo com
 * seleção de pipeline, safety switch, terminal em tempo real e
 * DataGrid de validação de vulnerabilidades.
 *
 * Motores Suportados:
 *   P1 — Recon Tradicional    (Nmap, Whatweb, headers, DNS, certificados)
 *   P2 — Crawler Agressivo    (Spider, dirbusting, captura de parâmetros)
 *   P3 — IA Active Attacker   (IA dispara payloads contextuais em endpoints)
 *
 * Safety Switch:
 *   SAFE (Carga Seca)         → Payloads Time-based / bypass lógico, ZERO destrutivos
 *   HOT  (Gêmeo Efêmero)     → Clonagem Docker, ataques destrutivos liberados em sandbox
 *
 * Protocolo WebSocket:
 *   Envio  → { action: "START_SCAN", target, pipeline, mode: "safe"|"hot" }
 *   Retorno → { action: "SCAN_RESULT" | "LOG" | "SCAN_ERROR", ... }
 *
 * Persistência: localStorage key = previswit_pentest_<hash_do_target>
 */

import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Play, Activity, AlertTriangle, Terminal,
  Shield, Flame, ChevronDown, ChevronRight,
  Database, TrendingUp, CheckCircle, XCircle,
  Clock, Wifi, WifiOff, Trash2, Search,
  Zap, Eye, BarChart2, ExternalLink, RefreshCw,
  Lock, Unlock, Settings,
} from 'lucide-react';

// ── Helpers ───────────────────────────────────────────────────────────────────

function severityColors(sev) {
  const s = (sev || '').toUpperCase();
  if (s === 'CRITICAL') return { bg: 'bg-rose-500/10', text: 'text-rose-400', border: 'border-rose-500/25', dot: 'bg-rose-500', glow: 'shadow-rose-500/20' };
  if (s === 'HIGH')     return { bg: 'bg-red-500/10',  text: 'text-red-400',  border: 'border-red-500/25',  dot: 'bg-red-500',  glow: 'shadow-red-500/20' };
  if (s === 'MEDIUM')   return { bg: 'bg-amber-500/10',text: 'text-amber-400',border: 'border-amber-500/25',dot: 'bg-amber-500',glow: 'shadow-amber-500/20' };
  if (s === 'LOW')      return { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/25', dot: 'bg-blue-500', glow: 'shadow-blue-500/20' };
  return                         { bg: 'bg-gray-500/10',text: 'text-gray-400', border: 'border-gray-500/25', dot: 'bg-gray-500', glow: '' };
}

function proofStatusColors(status) {
  const s = (status || '').toLowerCase();
  if (s.includes('confirm') || s === 'exploited') return { text: 'text-rose-400', bg: 'bg-rose-500/10', border: 'border-rose-500/25' };
  if (s.includes('false') || s === 'false_positive') return { text: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/25' };
  if (s.includes('pend')) return { text: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/25' };
  return { text: 'text-gray-400', bg: 'bg-gray-500/10', border: 'border-gray-500/25' };
}

function storageKey(target) {
  // Gera chave estável sem caracteres inválidos
  return 'previswit_pentest_' + (target || '').replace(/[^a-zA-Z0-9]/g, '_').slice(0, 80);
}

const LOG_COLORS = {
  system:  'text-blue-400',
  info:    'text-gray-300',
  debug:   'text-gray-500',
  success: 'text-emerald-400',
  error:   'text-rose-400',
  warn:    'text-amber-400',
  ai:      'text-purple-400',
};

// ── Pipeline metadata ─────────────────────────────────────────────────────────

const PIPELINES = [
  {
    id: 'p1',
    label: 'P1 — Recon Tradicional',
    description: 'Fingerprinting, DNS, TLS, headers, CVEs públicos via OSINTs.',
    color: 'text-blue-400',
    accentBg: 'bg-blue-500/10',
    accentBorder: 'border-blue-500/25',
  },
  {
    id: 'p2',
    label: 'P2 — Crawler Agressivo',
    description: 'Spider completo, dirbusting, enumeração de parâmetros e endpoints.',
    color: 'text-amber-400',
    accentBg: 'bg-amber-500/10',
    accentBorder: 'border-amber-500/25',
  },
  {
    id: 'p3',
    label: 'P3/P6 — IA Active Attacker',
    description: 'IA dispara payloads contextuais em endpoints mapeados. Requer Safety Switch.',
    color: 'text-rose-400',
    accentBg: 'bg-rose-500/10',
    accentBorder: 'border-rose-500/25',
  },
];

// ── Finding Row ───────────────────────────────────────────────────────────────

function FindingRow({ finding, index }) {
  const [expanded, setExpanded] = useState(false);

  const vuln     = finding.vulnerability || finding.name || finding.title || finding.description || '—';
  const endpoint = finding.endpoint || finding.url || finding.path || '—';
  const payload  = finding.payload || finding.ai_payload || finding.evidence || '—';
  const proof    = finding.proof_status || finding.status || 'Pendente';
  const sev      = finding.severity || finding.risk || 'MEDIUM';

  const sevC   = severityColors(sev);
  const proofC = proofStatusColors(proof);

  return (
    <div className="group border-b border-white/[0.04] last:border-0">
      <div
        onClick={() => setExpanded(e => !e)}
        className={`grid grid-cols-12 gap-2 items-center px-4 py-3 cursor-pointer
                    hover:bg-white/[0.025] transition-all duration-150
                    ${index % 2 === 0 ? 'bg-transparent' : 'bg-white/[0.01]'}`}
      >
        {/* # */}
        <div className="col-span-1 text-[10px] text-gray-600 font-mono select-none">
          #{String(index + 1).padStart(3, '0')}
        </div>

        {/* Vulnerability */}
        <div className="col-span-3 min-w-0">
          <p className="text-xs font-semibold text-gray-200 truncate">{vuln}</p>
        </div>

        {/* Endpoint */}
        <div className="col-span-3 min-w-0">
          <p className="text-[11px] font-mono text-gray-400 truncate">{endpoint}</p>
        </div>

        {/* Payload */}
        <div className="col-span-2 min-w-0">
          <p className="text-[11px] font-mono text-purple-400/80 truncate">{payload}</p>
        </div>

        {/* Proof Status */}
        <div className="col-span-1">
          <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-bold border
                           ${proofC.bg} ${proofC.text} ${proofC.border}`}>
            {proof.length > 12 ? proof.slice(0, 12) + '…' : proof}
          </span>
        </div>

        {/* Severity + Expand */}
        <div className="col-span-2 flex items-center justify-between gap-1">
          <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full border text-[9px] font-bold
                           ${sevC.bg} ${sevC.text} ${sevC.border}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${sevC.dot}`} />
            {sev.toUpperCase().slice(0, 4)}
          </span>
          <ChevronRight className={`w-3 h-3 text-gray-600 transition-transform duration-200 shrink-0 ${expanded ? 'rotate-90' : ''}`} />
        </div>
      </div>

      {/* Expanded */}
      {expanded && (
        <div className="px-4 py-4 bg-[#030710]/80 border-b border-white/[0.04]">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <p className="text-[9px] text-gray-600 uppercase tracking-wider font-bold mb-1">Endpoint Completo</p>
              <p className="text-xs font-mono text-gray-300 break-all">{endpoint}</p>
            </div>
            <div>
              <p className="text-[9px] text-gray-600 uppercase tracking-wider font-bold mb-1">Payload da IA</p>
              <pre className="text-[11px] font-mono text-purple-400 bg-black/40 rounded-lg p-2 overflow-x-auto whitespace-pre-wrap break-words max-h-24">
                {typeof payload === 'string' ? payload : JSON.stringify(payload, null, 2)}
              </pre>
            </div>
            {finding.detail && (
              <div className="col-span-2">
                <p className="text-[9px] text-gray-600 uppercase tracking-wider font-bold mb-1">Evidência / Output</p>
                <pre className="text-[11px] font-mono text-gray-400 bg-black/40 rounded-lg p-2 overflow-x-auto whitespace-pre-wrap break-words max-h-32">
                  {typeof finding.detail === 'string' ? finding.detail : JSON.stringify(finding.detail, null, 2)}
                </pre>
              </div>
            )}
            {finding.reference && (
              <div>
                <p className="text-[9px] text-gray-600 uppercase tracking-wider font-bold mb-1">Referência</p>
                <a href={finding.reference} target="_blank" rel="noopener noreferrer"
                   className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 transition-colors">
                  <ExternalLink className="w-3 h-3" /> {finding.reference}
                </a>
              </div>
            )}
            {finding.remediation && (
              <div>
                <p className="text-[9px] text-gray-600 uppercase tracking-wider font-bold mb-1">Remediação</p>
                <p className="text-xs text-emerald-400 leading-relaxed">{finding.remediation}</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Safety Switch ─────────────────────────────────────────────────────────────

function SafetySwitch({ mode, onChange, disabled }) {
  return (
    <div className="flex flex-col gap-2">
      <p className="text-[10px] text-gray-500 uppercase tracking-wider font-bold">Modo de Engajamento</p>
      <div className="flex gap-2">
        {/* SAFE */}
        <button
          type="button"
          onClick={() => onChange('safe')}
          disabled={disabled}
          className={`flex-1 flex items-center gap-2 px-3 py-2.5 rounded-xl border text-xs font-bold transition-all duration-200
                     ${mode === 'safe'
                       ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300'
                       : 'bg-white/[0.03] border-white/[0.08] text-gray-500 hover:border-white/20 hover:text-gray-300'
                     } disabled:opacity-40 disabled:cursor-not-allowed`}
        >
          <Shield className="w-3.5 h-3.5 shrink-0" />
          <div className="text-left">
            <div>Carga Seca</div>
            <div className={`text-[9px] font-normal mt-0.5 ${mode === 'safe' ? 'text-emerald-400/70' : 'text-gray-600'}`}>
              Produção · Payloads inofensivos
            </div>
          </div>
        </button>

        {/* HOT */}
        <button
          type="button"
          onClick={() => onChange('hot')}
          disabled={disabled}
          className={`flex-1 flex items-center gap-2 px-3 py-2.5 rounded-xl border text-xs font-bold transition-all duration-200
                     ${mode === 'hot'
                       ? 'bg-rose-500/15 border-rose-500/40 text-rose-300'
                       : 'bg-white/[0.03] border-white/[0.08] text-gray-500 hover:border-white/20 hover:text-gray-300'
                     } disabled:opacity-40 disabled:cursor-not-allowed`}
        >
          <Flame className="w-3.5 h-3.5 shrink-0" />
          <div className="text-left">
            <div>Gêmeo Efêmero</div>
            <div className={`text-[9px] font-normal mt-0.5 ${mode === 'hot' ? 'text-rose-400/70' : 'text-gray-600'}`}>
              Homologação · Ataques destrutivos
            </div>
          </div>
        </button>
      </div>

      {/* Warning when HOT */}
      {mode === 'hot' && (
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-rose-500/10 border border-rose-500/20 text-[10px] text-rose-400">
          <AlertTriangle className="w-3 h-3 shrink-0" />
          Modo destrutivo ativo. Use apenas em ambientes de homologação controlados.
        </div>
      )}
    </div>
  );
}

// ── Main Component ────────────────────────────────────────────────────────────

export default function EngagementsPage() {
  const [target,      setTarget]      = useState('');
  const [pipeline,    setPipeline]    = useState('p1');
  const [mode,        setMode]        = useState('safe');
  const [status,      setStatus]      = useState('idle');    // idle | scanning | success | error
  const [errorMsg,    setErrorMsg]    = useState(null);
  const [wsConnected, setWsConnected] = useState(false);
  const [logs,        setLogs]        = useState([]);
  const [results,     setResults]     = useState(null);
  const [metrics,     setMetrics]     = useState({ critical: 0, high: 0, medium: 0, low: 0, total: 0 });
  const [sevFilter,   setSevFilter]   = useState('ALL');
  const [lastTarget,  setLastTarget]  = useState('');

  const wsRef      = useRef(null);
  const logsEndRef = useRef(null);

  // ── Auto-scroll console ────────────────────────────────────────────────────
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const addLog = useCallback((text, type = 'info') => {
    const ts = new Date().toLocaleTimeString('pt-BR', { hour12: false });
    setLogs(prev => [...prev.slice(-500), { text, type, ts, id: Date.now() + Math.random() }]);
  }, []);

  // ── Hidratação do último laudo ─────────────────────────────────────────────
  useEffect(() => {
    const lastKey = localStorage.getItem('previswit_pentest_last_key');
    if (lastKey) {
      const cached = localStorage.getItem(storageKey(lastKey));
      if (cached) {
        try {
          const parsed = JSON.parse(cached);
          setResults(parsed);
          setLastTarget(lastKey);
          setTarget(lastKey);
          _calcMetrics(parsed);
          setStatus('success');
          addLog(`Laudo anterior carregado do cache: ${lastKey}`, 'system');
        } catch (_) {}
      }
    }
  }, []); // eslint-disable-line

  function _calcMetrics(data) {
    const findings = data?.findings_prioritized || data?.findings || data?.vulnerabilities || [];
    const count = (sev) => findings.filter(f => (f.severity || f.risk || '').toUpperCase() === sev).length;
    setMetrics({
      critical: count('CRITICAL'),
      high:     count('HIGH'),
      medium:   count('MEDIUM'),
      low:      count('LOW'),
      total:    findings.length,
    });
  }

  // ── WebSocket ──────────────────────────────────────────────────────────────
  useEffect(() => {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${proto}//${window.location.host}/ws/web_dashboard`;

    const connect = () => {
      try {
        wsRef.current = new WebSocket(wsUrl);

        wsRef.current.onopen = () => {
          setWsConnected(true);
          addLog('Canal WebSocket estabelecido com o servidor PreviSwit.', 'system');
        };

        wsRef.current.onmessage = (event) => {
          try {
            const msg = JSON.parse(event.data);

            if (msg.action === 'LOG') {
              // Classifica a mensagem do servidor pelo prefixo
              const text = msg.message || '';
              let type = 'info';
              if (text.includes('[DEBUG]') || text.startsWith('🔍'))  type = 'debug';
              if (text.includes('[AI]')   || text.startsWith('🤖'))   type = 'ai';
              if (text.includes('Erro')   || text.includes('ERROR'))  type = 'error';
              if (text.includes('sucesso')|| text.includes('✅'))      type = 'success';
              if (text.includes('[WARN]') || text.includes('⚠'))      type = 'warn';
              addLog(text, type);

            } else if (msg.action === 'SCAN_RESULT') {
              const data = msg.data || msg;
              setStatus('success');
              setResults(data);
              _calcMetrics(data);

              // Grava no localStorage
              const t = msg.target || target;
              localStorage.setItem(storageKey(t), JSON.stringify(data));
              localStorage.setItem('previswit_pentest_last_key', t);
              setLastTarget(t);

              const total = (data?.findings_prioritized || data?.findings || data?.vulnerabilities || []).length;
              addLog(`Pentest concluído para ${t} — ${total} finding${total !== 1 ? 's' : ''} encontrado${total !== 1 ? 's' : ''}.`, 'success');

            } else if (msg.action === 'SCAN_ERROR' || msg.status === 'SCAN_ERROR') {
              setStatus('error');
              setErrorMsg(msg.error || 'Erro desconhecido durante o scan.');
              addLog(`ERRO: ${msg.error || 'Falha sem detalhe'}`, 'error');

            } else if (msg.status === 'scanning') {
              addLog(`Agente escaneando: ${msg.target || ''}`, 'system');
            }
          } catch (e) {
            console.error('[EngagementsPage] Erro ao processar WS msg:', e);
          }
        };

        wsRef.current.onerror = () => {
          setWsConnected(false);
          addLog('Erro na conexão WebSocket.', 'error');
        };

        wsRef.current.onclose = (e) => {
          setWsConnected(false);
          addLog(`WebSocket desconectado (code: ${e.code}). Reconectando em 4s...`, 'system');
          setTimeout(connect, 4000);
        };
      } catch (err) {
        addLog(`Falha ao iniciar WebSocket: ${err.message}`, 'error');
      }
    };

    connect();
    return () => wsRef.current?.close(1000, 'Component unmounted');
  }, []); // eslint-disable-line

  // ── Handlers ──────────────────────────────────────────────────────────────

  const handleScan = (e) => {
    e.preventDefault();
    if (!target.trim()) return;

    if (!wsConnected) {
      setStatus('error');
      setErrorMsg('Agente offline. Aguarde a reconexão do WebSocket.');
      addLog('Tentativa de scan sem conexão WebSocket ativa.', 'error');
      return;
    }

    setStatus('scanning');
    setErrorMsg(null);
    setResults(null);
    setMetrics({ critical: 0, high: 0, medium: 0, low: 0, total: 0 });
    setLogs([]);
    setSevFilter('ALL');

    const pipelineMeta = PIPELINES.find(p => p.id === pipeline);
    addLog(`Iniciando ${pipelineMeta?.label || pipeline} em: ${target}`, 'system');
    addLog(`Modo: ${mode === 'hot' ? 'Gêmeo Efêmero (DESTRUTIVO)' : 'Carga Seca (Produção)'}`, mode === 'hot' ? 'warn' : 'system');

    wsRef.current.send(JSON.stringify({
      action:   'START_SCAN',
      target:   target.trim(),
      pipeline: pipeline,
      mode:     mode,
    }));
  };

  const handleClearCache = () => {
    if (!lastTarget) return;
    localStorage.removeItem(storageKey(lastTarget));
    localStorage.removeItem('previswit_pentest_last_key');
    setResults(null);
    setMetrics({ critical: 0, high: 0, medium: 0, low: 0, total: 0 });
    setStatus('idle');
    setLastTarget('');
    addLog('Cache de laudo removido.', 'system');
  };

  // ── Computed ───────────────────────────────────────────────────────────────

  const isScanning  = status === 'scanning';
  const allFindings = results
    ? (results.findings_prioritized || results.findings || results.vulnerabilities || [])
    : [];

  const filteredFindings = sevFilter === 'ALL'
    ? allFindings
    : allFindings.filter(f => (f.severity || f.risk || '').toUpperCase() === sevFilter);

  const SEV_TABS = [
    { key: 'ALL',      label: 'Todos',    count: allFindings.length,                          cls: 'text-white' },
    { key: 'CRITICAL', label: 'Critical', count: metrics.critical,                             cls: 'text-rose-400' },
    { key: 'HIGH',     label: 'High',     count: metrics.high,                                 cls: 'text-red-400' },
    { key: 'MEDIUM',   label: 'Medium',   count: metrics.medium,                               cls: 'text-amber-400' },
    { key: 'LOW',      label: 'Low',      count: metrics.low,                                  cls: 'text-blue-400' },
  ];

  const activePipeline = PIPELINES.find(p => p.id === pipeline);

  return (
    <div className="flex flex-col gap-6 w-full">

      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2.5">
            <Zap className="w-5 h-5 text-rose-400" />
            Pentest Contínuo
          </h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Orquestração DAST · Ataque Ativo · IA Active Attacker
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {/* WS indicator */}
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-white/[0.08] bg-white/[0.03]">
            {wsConnected
              ? <><span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" /><span className="text-[10px] text-emerald-400 font-semibold">Agente Online</span></>
              : <><span className="w-2 h-2 rounded-full bg-gray-600" /><span className="text-[10px] text-gray-500 font-semibold">Agente Offline</span></>
            }
          </div>
          {results && (
            <button
              onClick={handleClearCache}
              title="Limpar laudo em cache"
              className="p-2 rounded-lg border border-white/[0.08] text-gray-500 hover:text-red-400 hover:bg-red-500/10 hover:border-red-500/25 transition-all"
            >
              <Trash2 className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

      {/* ── Error Banner ───────────────────────────────────────────────── */}
      {status === 'error' && errorMsg && (
        <div className="flex items-center gap-3 px-4 py-3 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <p className="text-sm">{errorMsg}</p>
        </div>
      )}

      {/* ── Cockpit de Ataque ───────────────────────────────────────────── */}
      <div className="bg-gradient-to-b from-[#0d1421]/80 to-[#060b13]/90 border border-white/[0.06] rounded-2xl overflow-hidden">
        <div className={`h-[2px] w-full ${mode === 'hot'
          ? 'bg-gradient-to-r from-rose-500/60 to-orange-500/30'
          : 'bg-gradient-to-r from-blue-500/50 to-purple-500/20'}`}
        />
        <form onSubmit={handleScan} className="p-6 flex flex-col gap-5">

          {/* Target */}
          <div>
            <label className="text-[10px] text-gray-500 uppercase tracking-wider font-bold mb-2 block">
              Alvo — URL ou Swagger API
            </label>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-600" />
              <input
                type="text"
                value={target}
                onChange={e => setTarget(e.target.value)}
                disabled={isScanning}
                placeholder="https://api.empresa.com ou https://api.empresa.com/swagger.json"
                className="w-full bg-[#111827] border border-white/[0.08] rounded-xl pl-10 pr-4 py-3 text-sm text-white
                           placeholder:text-gray-600 focus:outline-none focus:border-blue-500/40
                           focus:ring-1 focus:ring-blue-500/20 transition-all disabled:opacity-50"
              />
            </div>
          </div>

          {/* Pipeline + Safety */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">

            {/* Pipeline selector */}
            <div>
              <p className="text-[10px] text-gray-500 uppercase tracking-wider font-bold mb-2">Motor de Ataque</p>
              <div className="flex flex-col gap-2">
                {PIPELINES.map(p => (
                  <button
                    key={p.id}
                    type="button"
                    onClick={() => !isScanning && setPipeline(p.id)}
                    disabled={isScanning}
                    className={`flex items-start gap-3 px-3 py-2.5 rounded-xl border text-left transition-all duration-150
                                ${pipeline === p.id
                                  ? `${p.accentBg} ${p.accentBorder} ${p.color}`
                                  : 'bg-white/[0.02] border-white/[0.07] text-gray-500 hover:border-white/15 hover:text-gray-300'
                                } disabled:opacity-40 disabled:cursor-not-allowed`}
                  >
                    <div className={`w-1.5 h-1.5 rounded-full mt-1.5 shrink-0 ${pipeline === p.id ? p.color.replace('text-', 'bg-') : 'bg-gray-600'}`} />
                    <div>
                      <p className="text-xs font-bold">{p.label}</p>
                      <p className={`text-[10px] font-normal mt-0.5 ${pipeline === p.id ? 'opacity-70' : 'text-gray-600'}`}>
                        {p.description}
                      </p>
                    </div>
                  </button>
                ))}
              </div>
            </div>

            {/* Safety Switch */}
            <div className="flex flex-col gap-5">
              <SafetySwitch mode={mode} onChange={setMode} disabled={isScanning} />

              {/* Launch button */}
              <button
                type="submit"
                disabled={isScanning || !target.trim() || !wsConnected}
                className={`w-full flex items-center justify-center gap-2.5 py-3.5 rounded-xl text-sm font-bold
                            transition-all duration-200 shadow-lg
                            ${isScanning
                              ? 'bg-gray-800 text-gray-500 cursor-not-allowed'
                              : mode === 'hot'
                                ? 'bg-rose-600 hover:bg-rose-500 text-white shadow-rose-500/25'
                                : 'bg-blue-600 hover:bg-blue-500 text-white shadow-blue-500/25'
                            } disabled:opacity-50 disabled:cursor-not-allowed`}
              >
                {isScanning ? (
                  <><span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Executando Pentest...</>
                ) : (
                  <><Play className="w-4 h-4" /> Iniciar Pentest Contínuo</>
                )}
              </button>

              {/* Current scan info */}
              {results && lastTarget && (
                <div className="flex items-center gap-2 px-3 py-2 rounded-xl bg-white/[0.03] border border-white/[0.06]">
                  <CheckCircle className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  <span className="text-[10px] text-gray-400 truncate">
                    Laudo ativo: <span className="font-mono text-emerald-400">{lastTarget}</span>
                  </span>
                </div>
              )}
            </div>
          </div>
        </form>
      </div>

      {/* ── Layout: Terminal + Métricas ────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

        {/* Terminal */}
        <div className="lg:col-span-2 flex flex-col rounded-2xl border border-white/[0.06] bg-[#060b13] overflow-hidden h-72">
          {/* Terminal topbar */}
          <div className="flex items-center justify-between px-4 py-2.5 border-b border-white/[0.05] bg-[#030710]/80 shrink-0">
            <div className="flex items-center gap-2.5">
              {/* Traffic lights */}
              <div className="flex gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-red-500/70" />
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500/70" />
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/70" />
              </div>
              <Terminal className="w-3.5 h-3.5 text-gray-500" />
              <span className="text-[11px] text-gray-500 font-mono">previswit-agent · {wsConnected ? 'connected' : 'offline'}</span>
            </div>
            <button
              onClick={() => setLogs([])}
              className="text-[10px] text-gray-600 hover:text-gray-300 transition-colors"
            >
              clear
            </button>
          </div>

          {/* Log area */}
          <div className="flex-1 p-3 overflow-y-auto font-mono text-[11px] space-y-0.5 scrollbar-thin">
            {logs.length === 0 ? (
              <span className="text-gray-700 italic">
                {'>'} Aguardando início do scan...
              </span>
            ) : (
              logs.map(l => (
                <div key={l.id} className="flex gap-2 leading-relaxed">
                  <span className="text-gray-700 shrink-0 select-none">{l.ts}</span>
                  <span className={LOG_COLORS[l.type] || 'text-gray-300'}>{l.text}</span>
                </div>
              ))
            )}
            <div ref={logsEndRef} />
          </div>
        </div>

        {/* KPI cards */}
        <div className="flex flex-col gap-3 h-72">
          {[
            { label: 'Critical', value: metrics.critical, color: 'text-rose-400',  glow: 'drop-shadow-[0_0_8px_rgba(244,63,94,0.5)]', border: 'border-rose-500/15' },
            { label: 'High',     value: metrics.high,     color: 'text-red-400',   glow: 'drop-shadow-[0_0_8px_rgba(239,68,68,0.5)]', border: 'border-red-500/15' },
            { label: 'Medium',   value: metrics.medium,   color: 'text-amber-400', glow: 'drop-shadow-[0_0_8px_rgba(245,158,11,0.4)]', border: 'border-amber-500/15' },
            { label: 'Total',    value: metrics.total,    color: 'text-white',      glow: '',                                            border: 'border-white/[0.06]' },
          ].map(kpi => (
            <div key={kpi.label}
                 className={`flex-1 flex items-center justify-between px-4 rounded-xl bg-gradient-to-b from-[#0d1421]/70 to-[#060b13]/60 border ${kpi.border}`}
            >
              <p className="text-[10px] text-gray-600 uppercase tracking-wider font-bold">{kpi.label}</p>
              <span className={`text-3xl font-black ${kpi.color} ${kpi.glow}`}>{kpi.value}</span>
            </div>
          ))}
        </div>
      </div>

      {/* ── DataGrid de Validação ───────────────────────────────────────── */}
      {results && (
        <div className="bg-gradient-to-b from-[#0d1421]/80 to-[#060b13]/90 border border-white/[0.06] rounded-2xl overflow-hidden">
          {/* Toolbar */}
          <div className="px-5 py-4 border-b border-white/[0.05] flex items-center justify-between flex-wrap gap-3">
            <div className="flex items-center gap-2.5">
              <span className="w-1 h-5 rounded-full bg-blue-500/60" />
              <h3 className="text-sm font-bold text-white">Findings Validados</h3>
              <span className="text-[10px] text-gray-500 bg-white/[0.04] border border-white/[0.06] px-2 py-0.5 rounded-md">
                {filteredFindings.length} / {allFindings.length}
              </span>
            </div>
            <div className="flex items-center gap-1">
              {SEV_TABS.filter(t => t.count > 0 || t.key === 'ALL').map(tab => (
                <button
                  key={tab.key}
                  onClick={() => setSevFilter(tab.key)}
                  className={`flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11px] font-semibold transition-all
                              ${sevFilter === tab.key
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
          <div className="grid grid-cols-12 gap-2 px-4 py-2.5 text-[9px] text-gray-500 uppercase tracking-wider font-bold border-b border-white/[0.04] bg-white/[0.02]">
            <div className="col-span-1">#</div>
            <div className="col-span-3">Vulnerabilidade</div>
            <div className="col-span-3">Endpoint Afetado</div>
            <div className="col-span-2">Payload IA</div>
            <div className="col-span-1">Status da Prova</div>
            <div className="col-span-2">Severidade</div>
          </div>

          {/* Rows */}
          <div className="max-h-[520px] overflow-y-auto">
            {filteredFindings.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 gap-3">
                <div className="w-12 h-12 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
                  <Shield className="w-5 h-5 text-emerald-400" />
                </div>
                <p className="text-sm font-semibold text-emerald-400">
                  {sevFilter === 'ALL' ? 'Nenhuma vulnerabilidade confirmada' : `Sem findings de severidade ${sevFilter}`}
                </p>
              </div>
            ) : (
              filteredFindings.map((f, i) => (
                <FindingRow key={`${f.vulnerability || f.name || i}-${i}`} finding={f} index={i} />
              ))
            )}
          </div>
        </div>
      )}

      {/* ── Empty state ─────────────────────────────────────────────────── */}
      {!results && !isScanning && (
        <div className="flex flex-col items-center justify-center p-16 border border-dashed border-white/[0.06] rounded-2xl bg-gradient-to-b from-[#0d1421]/30 to-transparent">
          <div className="relative mb-6">
            <div className="w-16 h-16 rounded-2xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center">
              <Zap className="w-7 h-7 text-blue-400/60" />
            </div>
            <div className="absolute -bottom-1 -right-1 w-5 h-5 rounded-full bg-rose-500/20 border border-rose-500/30 flex items-center justify-center">
              <Play className="w-2.5 h-2.5 text-rose-400" />
            </div>
          </div>
          <p className="text-sm font-semibold text-gray-300 text-center">Aguardando engajamento</p>
          <p className="text-xs text-gray-600 text-center mt-2 max-w-sm leading-relaxed">
            Configure o alvo, selecione o motor e o modo de engajamento acima.
            Os resultados aparecerão aqui em tempo real.
          </p>
        </div>
      )}

    </div>
  );
}
