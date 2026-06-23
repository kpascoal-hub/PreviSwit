import React, { useState, useEffect, useCallback, useRef } from 'react';

// ─── Mapa de cores (classes Tailwind completas — sem template strings dinâmicas) ─
const COLOR_MAP = {
  green:   { bg: 'bg-green-600/20',   border: 'border-green-500/30',   text: 'text-green-400'   },
  orange:  { bg: 'bg-orange-600/20',  border: 'border-orange-500/30',  text: 'text-orange-400'  },
  red:     { bg: 'bg-red-600/20',     border: 'border-red-500/30',     text: 'text-red-400'     },
  yellow:  { bg: 'bg-yellow-600/20',  border: 'border-yellow-500/30',  text: 'text-yellow-400'  },
  blue:    { bg: 'bg-blue-600/20',    border: 'border-blue-500/30',    text: 'text-blue-400'    },
  indigo:  { bg: 'bg-indigo-600/20',  border: 'border-indigo-500/30',  text: 'text-indigo-400'  },
  purple:  { bg: 'bg-purple-600/20',  border: 'border-purple-500/30',  text: 'text-purple-400'  },
  teal:    { bg: 'bg-teal-600/20',    border: 'border-teal-500/30',    text: 'text-teal-400'    },
  cyan:    { bg: 'bg-cyan-600/20',    border: 'border-cyan-500/30',    text: 'text-cyan-400'    },
  emerald: { bg: 'bg-emerald-600/20', border: 'border-emerald-500/30', text: 'text-emerald-400' },
  violet:  { bg: 'bg-violet-600/20',  border: 'border-violet-500/30',  text: 'text-violet-400'  },
};
const defaultColor = { bg: 'bg-gray-600/20', border: 'border-gray-500/30', text: 'text-gray-400' };
function getColor(k) { return COLOR_MAP[k] || defaultColor; }

// ─── Severity badge helper ────────────────────────────────────────────────────
const SEV_STYLES = {
  CRITICAL: 'bg-red-500/15 text-red-400 border-red-500/30',
  HIGH:     'bg-orange-500/15 text-orange-400 border-orange-500/30',
  MEDIUM:   'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  LOW:      'bg-blue-500/15 text-blue-400 border-blue-500/30',
  INFO:     'bg-gray-500/15 text-gray-400 border-gray-500/30',
};
function SevBadge({ sev }) {
  const s = SEV_STYLES[(sev || '').toUpperCase()] || SEV_STYLES.INFO;
  return (
    <span className={`text-xs font-semibold border px-2 py-0.5 rounded-full ${s}`}>
      {sev || 'INFO'}
    </span>
  );
}

// ─── IntegrationCard ─────────────────────────────────────────────────────────
function IntegrationCard({ item }) {
  const { bg, border } = getColor(item.color);
  const isActive = item.active === true;
  return (
    <div className={`bg-[#0d1421] border border-white/5 rounded-xl p-5 flex items-start gap-4
      transition-all duration-300 hover:border-white/10 hover:bg-[#101828]
      ${isActive ? 'opacity-100' : 'opacity-40 grayscale'}`}
    >
      <div className={`w-10 h-10 flex-shrink-0 rounded-lg border flex items-center justify-center text-lg
        transition-colors duration-300
        ${isActive ? `${bg} ${border}` : 'bg-gray-800/50 border-gray-700/40'}`}
      >
        {item.icon}
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-semibold text-white truncate">{item.name}</p>
        <p className="text-xs text-gray-500 mt-0.5 truncate">{item.desc}</p>
        {isActive && item.version && (
          <p className="text-xs text-gray-600 mt-1 font-mono truncate">{item.version}</p>
        )}
        {isActive && item.path && !item.version && (
          <p className="text-xs text-gray-600 mt-1 font-mono truncate">{item.path}</p>
        )}
      </div>
      <div className="flex-shrink-0">
        {isActive ? (
          <span className="text-xs bg-green-500/15 text-green-400 border border-green-500/25 px-2 py-1 rounded-full whitespace-nowrap">✓ Ativo</span>
        ) : (
          <span className="text-xs bg-gray-500/10 text-gray-500 border border-gray-600/20 px-2 py-1 rounded-full whitespace-nowrap">Não Instalado</span>
        )}
      </div>
    </div>
  );
}

// ─── IntegrationSection ───────────────────────────────────────────────────────
function IntegrationSection({ title, subtitle, items, loading }) {
  if (loading) {
    return (
      <div className="mb-8">
        <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">{title}</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="bg-[#0d1421] border border-white/5 rounded-xl p-5 flex items-center gap-4 animate-pulse">
              <div className="w-10 h-10 rounded-lg bg-gray-800/60 flex-shrink-0" />
              <div className="flex-1 space-y-2">
                <div className="h-3 bg-gray-700/60 rounded w-3/4" />
                <div className="h-2 bg-gray-800/60 rounded w-1/2" />
              </div>
              <div className="h-5 w-16 bg-gray-800/60 rounded-full" />
            </div>
          ))}
        </div>
      </div>
    );
  }
  if (!items || items.length === 0) return null;
  const activeCount = items.filter(i => i.active).length;
  return (
    <div className="mb-8">
      <div className="flex items-center gap-3 mb-3">
        <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">{title}</h3>
        <span className="text-xs text-gray-600">{subtitle || `${activeCount} / ${items.length} ativos`}</span>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {items.map(item => <IntegrationCard key={item.id || item.name} item={item} />)}
      </div>
    </div>
  );
}

// ─── ASPM Parser Tool config ──────────────────────────────────────────────────
const ASPM_TOOLS = [
  {
    id:       'semgrep',
    name:     'Semgrep',
    type:     'SAST',
    icon:     '🔍',
    color:    'cyan',
    badgeColor: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/25',
    desc:     'Static Application Security Testing — analisa código-fonte com regras customizáveis.',
    example:  'semgrep --json --config=auto src/ > semgrep-output.json',
    endpoint: '/api/v1/integrations/parsers/semgrep',
  },
  {
    id:       'gitleaks',
    name:     'Gitleaks',
    type:     'Secrets',
    icon:     '🔑',
    color:    'violet',
    badgeColor: 'text-violet-400 bg-violet-500/10 border-violet-500/25',
    desc:     'Detecção de segredos e credenciais expostos em repositórios Git.',
    example:  'gitleaks detect --source . --report-format json --report-path gitleaks.json',
    endpoint: '/api/v1/integrations/parsers/gitleaks',
  },
  {
    id:       'checkov',
    name:     'Checkov',
    type:     'IaC',
    icon:     '🏗️',
    color:    'emerald',
    badgeColor: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/25',
    desc:     'Infrastructure as Code Security — Terraform, Kubernetes, Dockerfile e mais.',
    example:  'checkov -d ./terraform -o json > checkov-results.json',
    endpoint: '/api/v1/integrations/parsers/checkov',
  },
];

// ─── Upload state per tool ────────────────────────────────────────────────────
function useParserState() {
  return useState(() =>
    Object.fromEntries(ASPM_TOOLS.map(t => [t.id, {
      dragging: false,
      file:     null,
      loading:  false,
      result:   null,
      error:    null,
    }]))
  );
}

// ─── DropZone ────────────────────────────────────────────────────────────────
function DropZone({ toolId, state, onFileSelect, onDrop, onDragOver, onDragLeave }) {
  const inputRef = useRef(null);
  const { dragging, file } = state;
  return (
    <div
      id={`dropzone-${toolId}`}
      className={`relative border-2 border-dashed rounded-xl p-6 text-center cursor-pointer
        transition-all duration-200
        ${dragging
          ? 'border-indigo-400 bg-indigo-500/10 scale-[1.01]'
          : file
            ? 'border-green-500/40 bg-green-500/5'
            : 'border-white/10 bg-white/[0.02] hover:border-white/20 hover:bg-white/[0.04]'
        }`}
      onClick={() => inputRef.current?.click()}
      onDrop={e => { e.preventDefault(); onDrop(toolId, e.dataTransfer.files[0]); }}
      onDragOver={e => { e.preventDefault(); onDragOver(toolId); }}
      onDragLeave={() => onDragLeave(toolId)}
    >
      <input
        ref={inputRef}
        id={`input-file-${toolId}`}
        type="file"
        accept=".json,application/json"
        className="hidden"
        onChange={e => onFileSelect(toolId, e.target.files[0])}
      />
      {file ? (
        <div className="flex items-center justify-center gap-3">
          <span className="text-2xl">📄</span>
          <div className="text-left">
            <p className="text-sm font-medium text-green-400">{file.name}</p>
            <p className="text-xs text-gray-500">{(file.size / 1024).toFixed(1)} KB — pronto para envio</p>
          </div>
        </div>
      ) : (
        <div>
          <p className="text-2xl mb-2">📂</p>
          <p className="text-sm text-gray-400">Arraste o <code className="text-indigo-400 bg-indigo-400/10 px-1 rounded">.json</code> aqui</p>
          <p className="text-xs text-gray-600 mt-1">ou clique para selecionar o arquivo</p>
        </div>
      )}
    </div>
  );
}

// ─── Result panel ─────────────────────────────────────────────────────────────
function IngestResult({ result, error }) {
  if (error) {
    return (
      <div className="mt-3 p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-xs flex items-start gap-2">
        <span className="flex-shrink-0 mt-0.5">⚠️</span>
        <span>{error}</span>
      </div>
    );
  }
  if (!result) return null;

  const bySev = result.by_severity || {};
  const sevOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

  return (
    <div className="mt-3 p-3 rounded-lg bg-green-500/10 border border-green-500/20 space-y-2">
      <div className="flex items-center gap-2 text-green-400 text-xs font-semibold">
        <span>✅</span>
        <span>Ingestão concluída — {result.imported} achados importados</span>
      </div>
      <div className="flex flex-wrap gap-2">
        {sevOrder.filter(s => bySev[s] > 0).map(s => (
          <span key={s} className={`text-xs border px-2 py-0.5 rounded-full font-semibold ${SEV_STYLES[s]}`}>
            {bySev[s]} {s}
          </span>
        ))}
      </div>
      {result.duplicates_skipped > 0 && (
        <p className="text-xs text-gray-500">
          {result.duplicates_skipped} achado(s) ignorado(s) por duplicata
        </p>
      )}
      {result.parsed_total > 0 && result.imported === 0 && (
        <p className="text-xs text-yellow-500">
          {result.parsed_total} achado(s) encontrado(s) — todos já existem na plataforma.
        </p>
      )}
    </div>
  );
}

// ─── ASPMParserCard ──────────────────────────────────────────────────────────
function ASPMParserCard({ tool, state, onFileSelect, onDrop, onDragOver, onDragLeave, onSubmit, onClear }) {
  const { bg, border } = getColor(tool.color);
  return (
    <div className="bg-[#0d1421] border border-white/5 rounded-xl p-5 flex flex-col gap-4 hover:border-white/10 transition-colors duration-200">

      {/* Header */}
      <div className="flex items-center gap-3">
        <div className={`w-10 h-10 flex-shrink-0 rounded-lg ${bg} ${border} border flex items-center justify-center text-lg`}>
          {tool.icon}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <p className="text-sm font-semibold text-white">{tool.name}</p>
            <span className={`text-xs font-medium border px-2 py-0.5 rounded-full ${tool.badgeColor}`}>
              {tool.type}
            </span>
          </div>
          <p className="text-xs text-gray-500 mt-0.5 leading-snug">{tool.desc}</p>
        </div>
      </div>

      {/* CLI hint */}
      <div className="bg-[#07090f] rounded-lg px-3 py-2 flex items-start gap-2">
        <span className="text-gray-600 text-xs flex-shrink-0 mt-0.5 select-none">$</span>
        <code className="text-xs text-gray-400 break-all font-mono leading-relaxed">{tool.example}</code>
      </div>

      {/* Drop zone */}
      <DropZone
        toolId={tool.id}
        state={state}
        onFileSelect={onFileSelect}
        onDrop={onDrop}
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
      />

      {/* Actions */}
      <div className="flex gap-2">
        <button
          id={`btn-ingest-${tool.id}`}
          disabled={!state.file || state.loading}
          onClick={() => onSubmit(tool)}
          className={`flex-1 py-2 rounded-lg text-sm font-semibold transition-all duration-200 flex items-center justify-center gap-2
            ${state.file && !state.loading
              ? 'bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg shadow-indigo-500/20'
              : 'bg-white/5 text-gray-600 cursor-not-allowed'
            }`}
        >
          {state.loading ? (
            <>
              <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
              </svg>
              Processando…
            </>
          ) : (
            <>
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/>
              </svg>
              Ingerir Achados
            </>
          )}
        </button>

        {(state.file || state.result || state.error) && (
          <button
            id={`btn-clear-${tool.id}`}
            onClick={() => onClear(tool.id)}
            title="Limpar"
            className="px-3 py-2 rounded-lg text-gray-500 hover:text-gray-300 hover:bg-white/5 transition-colors text-sm"
          >
            ✕
          </button>
        )}
      </div>

      {/* Result / error */}
      <IngestResult result={state.result} error={state.error} />
    </div>
  );
}

// ─── Tabs ─────────────────────────────────────────────────────────────────────
const TABS = [
  { id: 'tools',   label: 'Motor de Pentest',   icon: '🛠️' },
  { id: 'parsers', label: 'ASPM Parsers',        icon: '📥' },
  { id: 'api',     label: 'APIs & IA',           icon: '🔑' },
  { id: 'custom',  label: 'Configuradas',        icon: '⚙️' },
];

// ─── Main ─────────────────────────────────────────────────────────────────────
const CAP_URL    = '/api/v1/integrations/capabilities';
const POLL_MS    = 30_000;

export default function IntegrationsPage() {
  const [tab, setTab]         = useState('tools');
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);
  const [lastFetch, setLastFetch] = useState(null);

  // Parser states
  const [parserStates, setParserStates] = useParserState();

  // ── Capabilities fetch ────────────────────────────────────────────────
  const fetchCapabilities = useCallback(async () => {
    try {
      const res = await fetch(CAP_URL);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setData(await res.json());
      setError(null);
      setLastFetch(new Date());
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchCapabilities(); }, [fetchCapabilities]);
  useEffect(() => {
    const t = setInterval(fetchCapabilities, POLL_MS);
    return () => clearInterval(t);
  }, [fetchCapabilities]);

  // ── Parser helpers ────────────────────────────────────────────────────
  const updateParser = (id, patch) =>
    setParserStates(prev => ({ ...prev, [id]: { ...prev[id], ...patch } }));

  const handleFileSelect  = (id, file) => updateParser(id, { file, result: null, error: null });
  const handleDrop        = (id, file) => file && updateParser(id, { file, dragging: false, result: null, error: null });
  const handleDragOver    = (id)       => updateParser(id, { dragging: true });
  const handleDragLeave   = (id)       => updateParser(id, { dragging: false });
  const handleClear       = (id)       => updateParser(id, { file: null, result: null, error: null, dragging: false });

  const handleSubmit = async (tool) => {
    const st = parserStates[tool.id];
    if (!st.file) return;
    updateParser(tool.id, { loading: true, result: null, error: null });

    try {
      const text = await st.file.text();
      const json = JSON.parse(text);

      const res = await fetch(tool.endpoint, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(json),
      });

      const payload = await res.json();

      if (!res.ok) {
        throw new Error(payload.detail || `Servidor retornou HTTP ${res.status}`);
      }

      updateParser(tool.id, { loading: false, result: payload, file: null });
    } catch (e) {
      updateParser(tool.id, { loading: false, error: e.message });
    }
  };

  // ── Derived ──────────────────────────────────────────────────────────
  const agentConnected = data?.agent_connected ?? false;
  const lastSeen       = data?.last_seen ? new Date(data.last_seen).toLocaleString('pt-BR') : null;

  // ── Render ────────────────────────────────────────────────────────────
  return (
    <div className="flex flex-col h-full">

      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div className="mb-6 flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h2 className="text-xl font-semibold text-white">Integrações</h2>
          <p className="text-sm text-gray-500 mt-1">
            Ferramentas de scan, ASPM parsers, CI/CD e notificações — status em tempo real do motor.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className={`flex items-center gap-2 text-xs px-3 py-1.5 rounded-full border ${
            loading
              ? 'text-gray-400 border-gray-700/40 bg-gray-800/30'
              : agentConnected
                ? 'text-green-400 border-green-500/25 bg-green-500/10'
                : 'text-yellow-500 border-yellow-500/25 bg-yellow-500/10'
          }`}>
            <span className={`w-1.5 h-1.5 rounded-full ${
              loading ? 'bg-gray-500' : agentConnected ? 'bg-green-400 animate-pulse' : 'bg-yellow-500'
            }`} />
            {loading ? 'Conectando…' : agentConnected ? 'Agente Conectado' : 'Aguardando Agente'}
          </div>

          <button
            id="btn-refresh-integrations"
            onClick={() => { setLoading(true); fetchCapabilities(); }}
            title="Atualizar"
            className="p-1.5 rounded-lg text-gray-500 hover:text-gray-300 hover:bg-white/5 transition-colors"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
          </button>
        </div>
      </div>

      {/* last seen */}
      {lastSeen && !loading && (
        <p className="text-xs text-gray-600 mb-4">
          Último report: <span className="text-gray-500">{lastSeen}</span>
          {lastFetch && <> · Atualizado: <span className="text-gray-500">{lastFetch.toLocaleTimeString('pt-BR')}</span></>}
        </p>
      )}

      {/* error banner */}
      {error && (
        <div className="mb-4 px-4 py-3 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 text-sm flex items-center gap-2">
          <svg className="w-4 h-4 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
          </svg>
          {error} — Verifique se o servidor está acessível.
        </div>
      )}

      {/* ── Tab bar ────────────────────────────────────────────────────── */}
      <div className="flex gap-1 mb-6 border-b border-white/5 pb-0">
        {TABS.map(t => (
          <button
            key={t.id}
            id={`tab-${t.id}`}
            onClick={() => setTab(t.id)}
            className={`flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium rounded-t-lg transition-all duration-150
              ${tab === t.id
                ? 'text-white border-b-2 border-indigo-400 bg-indigo-500/5 -mb-px'
                : 'text-gray-500 hover:text-gray-300 hover:bg-white/5'
              }`}
          >
            <span>{t.icon}</span>
            {t.label}
            {/* Badge de novidade na aba de parsers */}
            {t.id === 'parsers' && (
              <span className="text-xs bg-indigo-500/20 text-indigo-400 border border-indigo-500/30 px-1.5 py-0.5 rounded-full leading-none">
                ASPM
              </span>
            )}
          </button>
        ))}
      </div>

      {/* ── Tab: Motor de Pentest ───────────────────────────────────────── */}
      {tab === 'tools' && (
        <IntegrationSection
          title="🛠️ Ferramentas de Pentest"
          items={data?.pentest_tools}
          loading={loading}
        />
      )}

      {/* ── Tab: ASPM Parsers ───────────────────────────────────────────── */}
      {tab === 'parsers' && (
        <div>
          {/* Intro banner */}
          <div className="mb-6 p-4 rounded-xl bg-indigo-500/5 border border-indigo-500/15 flex items-start gap-3">
            <span className="text-2xl flex-shrink-0">📥</span>
            <div>
              <p className="text-sm font-semibold text-indigo-300 mb-1">Ingestão de Resultados ASPM</p>
              <p className="text-xs text-gray-400 leading-relaxed">
                Faça upload do <strong className="text-gray-300">JSON bruto</strong> gerado por cada ferramenta.
                Os achados são normalizados, deduplicados e persistidos automaticamente em <strong className="text-gray-300">Findings</strong>.
              </p>
            </div>
          </div>

          {/* Parser cards grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            {ASPM_TOOLS.map(tool => (
              <ASPMParserCard
                key={tool.id}
                tool={tool}
                state={parserStates[tool.id]}
                onFileSelect={handleFileSelect}
                onDrop={handleDrop}
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onSubmit={handleSubmit}
                onClear={handleClear}
              />
            ))}
          </div>

          {/* How it works */}
          <div className="mt-8 p-4 rounded-xl bg-white/[0.02] border border-white/5">
            <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Como funciona</p>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs text-gray-500">
              <div className="flex items-start gap-2">
                <span className="w-5 h-5 rounded-full bg-indigo-500/20 text-indigo-400 flex items-center justify-center flex-shrink-0 font-bold">1</span>
                <div><strong className="text-gray-400">Execute a ferramenta</strong> no seu repositório e gere o JSON de output com os comandos indicados.</div>
              </div>
              <div className="flex items-start gap-2">
                <span className="w-5 h-5 rounded-full bg-indigo-500/20 text-indigo-400 flex items-center justify-center flex-shrink-0 font-bold">2</span>
                <div><strong className="text-gray-400">Faça upload do JSON</strong> arrastando ou clicando na área de drop de cada parser.</div>
              </div>
              <div className="flex items-start gap-2">
                <span className="w-5 h-5 rounded-full bg-indigo-500/20 text-indigo-400 flex items-center justify-center flex-shrink-0 font-bold">3</span>
                <div><strong className="text-gray-400">Os achados aparecem</strong> em <strong className="text-indigo-400">Findings</strong> normalizados e deduplicados, prontos para triagem.</div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Tab: APIs & IA ──────────────────────────────────────────────── */}
      {tab === 'api' && (
        <IntegrationSection
          title="🔑 Integrações de API & IA"
          items={data?.api_integrations}
          loading={loading}
        />
      )}

      {/* ── Tab: Configuradas ───────────────────────────────────────────── */}
      {tab === 'custom' && (
        <>
          {data?.configured_integrations?.length > 0 ? (
            <IntegrationSection
              title="⚙️ Integrações Configuradas"
              subtitle={`${data.configured_integrations.length} configurada(s)`}
              items={data.configured_integrations.map(ci => ({
                id:     ci.id,
                name:   ci.name,
                desc:   ci.provider || ci.type || 'Integração customizada',
                icon:   '🔗',
                color:  'blue',
                active: ci.enabled !== false,
              }))}
              loading={false}
            />
          ) : (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <span className="text-4xl mb-3">🔗</span>
              <p className="text-sm text-gray-400 font-medium">Nenhuma integração configurada</p>
              <p className="text-xs text-gray-600 mt-1">Use a API <code className="text-indigo-400">POST /api/v1/integrations</code> para adicionar.</p>
            </div>
          )}
        </>
      )}

      {/* ── Footer summary ──────────────────────────────────────────────── */}
      {data && !loading && (
        <div className="mt-auto pt-6 border-t border-white/5">
          <div className="flex gap-6 text-xs text-gray-600">
            <span>Ferramentas ativas: <strong className="text-gray-400">{data.summary?.active_tools ?? 0}/{data.summary?.total_tools ?? 0}</strong></span>
            <span>APIs configuradas: <strong className="text-gray-400">{data.summary?.active_apis ?? 0}/{data.summary?.total_apis ?? 0}</strong></span>
            <span>Parsers ASPM: <strong className="text-indigo-400">3</strong></span>
          </div>
        </div>
      )}
    </div>
  );
}
