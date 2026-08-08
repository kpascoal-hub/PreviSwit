import React, { useState, useEffect, useCallback, useRef } from 'react';
import { NavLink } from 'react-router-dom';
import {
  GitBranch, ArrowLeft, Link2, RefreshCw, AlertTriangle,
  Clock, Settings, FileText, ChevronDown, CheckCircle, Shield,
  Zap, Activity, Database, Code2, Terminal, TrendingUp, Eye,
  X, Folder, File, Plus, Minus, ChevronRight, Bug, Lock,
  Server, Info, AlertOctagon, BrainCircuit, Sparkles,
} from 'lucide-react';
import RiskGraphCanvas from './RiskGraphCanvas';

const API = '/api/v1';

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('pt-BR', { day: '2-digit', month: 'short', year: 'numeric' });
}

function langColor(lang) {
  const map = {
    JavaScript: '#f7df1e', TypeScript: '#3178c6', Python: '#3572A5',
    Java: '#b07219', Go: '#00ADD8', Rust: '#dea584', Ruby: '#701516',
    C: '#555555', 'C++': '#f34b7d', 'C#': '#178600', PHP: '#4F5D95',
  };
  return map[lang] || '#8b949e';
}

// ── Extract structured findings from raw scanner_results ─────────────────────
function extractFindings(sr) {
  if (!sr) return [];
  const out = [];
  const strip = p => (p || '—').replace(/^\/tmp\/[^/]+\//, '');

  // Semgrep
  for (const r of (sr.semgrep?.results || [])) {
    const sev = (r.extra?.severity || 'MEDIUM').toUpperCase();
    if (!['HIGH', 'CRITICAL'].includes(sev)) continue;
    out.push({
      tool: 'semgrep', ruleId: r.check_id || '—',
      file: strip(r.path), line: r.start?.line, lineEnd: r.end?.line,
      message: r.extra?.message || '—', severity: sev,
    });
  }

  // Trivy
  for (const result of (sr.trivy?.Results || [])) {
    for (const v of (result.Vulnerabilities || [])) {
      const sev = (v.Severity || 'MEDIUM').toUpperCase();
      if (!['HIGH', 'CRITICAL'].includes(sev)) continue;
      out.push({
        tool: 'trivy', ruleId: v.VulnerabilityID || '—',
        file: result.Target || '—', line: null, lineEnd: null,
        message: v.Title || v.Description || '—', severity: sev,
        pkg: v.PkgName, installed: v.InstalledVersion, fixed: v.FixedVersion,
        description: v.Description,
      });
    }
  }

  // Gitleaks
  for (const leak of (Array.isArray(sr.gitleaks) ? sr.gitleaks : [])) {
    out.push({
      tool: 'gitleaks', ruleId: leak.RuleID || '—',
      file: strip(leak.File), line: leak.StartLine, lineEnd: null,
      message: leak.Description || 'Segredo exposto', severity: 'HIGH',
      match: leak.Match ? `${String(leak.Match).slice(0, 50)}…` : undefined,
    });
  }

  // Checkov
  const checkovList = Array.isArray(sr.checkov) ? sr.checkov : [sr.checkov].filter(Boolean);
  for (const rep of checkovList) {
    for (const ch of (rep?.results?.failed_checks || [])) {
      out.push({
        tool: 'checkov', ruleId: ch.check_id || '—',
        file: strip(ch.file_path), line: ch.file_line_range?.[0], lineEnd: ch.file_line_range?.[1],
        message: ch.check_name || '—', severity: 'HIGH',
        resource: ch.resource,
      });
    }
  }
  return out;
}

// ── SastScanPanel ─────────────────────────────────────────────────────────────

const PENDING_SCANS_KEY = 'previswit_pending_scans';

function savePendingScan(scanId, repoName, repoOwner) {
  try {
    const existing = JSON.parse(localStorage.getItem(PENDING_SCANS_KEY) || '[]');
    const filtered = existing.filter(s => s.repoName !== repoName); // replace if re-scan
    filtered.push({ scanId, repoName, repoOwner, startedAt: Date.now() });
    localStorage.setItem(PENDING_SCANS_KEY, JSON.stringify(filtered));
  } catch {}
}

function removePendingScan(scanId) {
  try {
    const existing = JSON.parse(localStorage.getItem(PENDING_SCANS_KEY) || '[]');
    localStorage.setItem(PENDING_SCANS_KEY, JSON.stringify(existing.filter(s => s.scanId !== scanId)));
  } catch {}
}

function SastScanPanel({ repo, onClose, onScanComplete }) {
  const owner   = repo.owner || '';
  const repoName = repo.name || '';
  const repoUrl = `https://github.com/${owner}/${repoName}.git`;

  // Config state
  const [scope, setScope] = useState('full');          // 'full' | 'specific'
  const [repoTree, setRepoTree] = useState([]);
  const [selectedPaths, setSelectedPaths] = useState(new Set());
  const [customInput, setCustomInput] = useState('');
  const [customPaths, setCustomPaths] = useState([]);
  const [loadingTree, setLoadingTree] = useState(false);
  const [aiLevel, setAiLevel] = useState('EXECUTIVO');
  const [runOnce, setRunOnce] = useState(true);
  const [intervalValue, setIntervalValue] = useState('30');
  const [intervalUnit, setIntervalUnit] = useState('MINUTES');

  // Scan state
  const [scanStatus, setScanStatus] = useState(null);
  const [scanId, setScanId] = useState(null);
  const [scanData, setScanData] = useState(null);
  const [activeTab, setActiveTab] = useState('config');
  const [isGeneratingPdf, setIsGeneratingPdf] = useState(false);
  const [toast, setToast] = useState(null);
  const [showFindings, setShowFindings] = useState(false);
  const [aiInsightsText, setAiInsightsText] = useState('');
  const [aiInsightsLoading, setAiInsightsLoading] = useState(false);

  const showToast = (msg) => { setToast(msg); setTimeout(() => setToast(null), 4000); };

  // Hydrate cached result
  useEffect(() => {
    try {
      const cached = localStorage.getItem('previswit_sast_current_view');
      if (cached) {
        const parsed = JSON.parse(cached);
        if (parsed.target === repo.name) {
          setScanData(parsed.data);
          setScanStatus('CONCLUÍDO');
          setActiveTab('results');
        }
      }
    } catch {}
  }, [repo.name]);

  // Fetch top-level tree from GitHub
  const fetchRepoTree = useCallback(async () => {
    const token = sessionStorage.getItem('GITHUB_TOKEN');
    if (!token || !owner || !repoName) return;
    setLoadingTree(true);
    try {
      const res = await fetch(
        `https://api.github.com/repos/${owner}/${repoName}/contents`,
        { headers: { Authorization: `token ${token}` } },
      );
      if (res.ok) {
        const items = await res.json();
        setRepoTree(
          Array.isArray(items)
            ? items.sort((a, b) => {
                if (a.type !== b.type) return a.type === 'dir' ? -1 : 1;
                return a.name.localeCompare(b.name);
              })
            : [],
        );
      }
    } catch {}
    setLoadingTree(false);
  }, [owner, repoName]);

  useEffect(() => { if (scope === 'specific') fetchRepoTree(); }, [scope, fetchRepoTree]);

  // Polling
  useEffect(() => {
    let iv;
    if (scanId && (scanStatus === 'PENDING' || scanStatus === 'RUNNING')) {
      iv = setInterval(async () => {
        try {
          const res = await fetch(`${API}/sast/scan-status/${scanId}`);
          if (res.ok) {
            const d = await res.json();
            setScanStatus(d.status);
            if (d.status === 'CONCLUÍDO') {
              setScanData(d.data);
              setActiveTab('results');
              localStorage.setItem('previswit_sast_current_view',
                JSON.stringify({ target: repoName, data: d.data }));
              removePendingScan(scanId);
              if (onScanComplete) onScanComplete(repoName, d.data);
              clearInterval(iv);
            } else if (d.status === 'ERROR') {
              removePendingScan(scanId);
              clearInterval(iv);
            }
          }
        } catch {}
      }, 3000);
    }
    return () => clearInterval(iv);
  }, [scanId, scanStatus, repo.name, onScanComplete]);

  const handleStartScan = async () => {
    setScanStatus('PENDING');
    setScanData(null);
    localStorage.removeItem('previswit_sast_current_view');

    const paths = scope === 'specific'
      ? [...selectedPaths, ...customPaths].filter(Boolean)
      : [];

    let intervalMinutes = 0;
    if (!runOnce) {
      const val = parseInt(intervalValue, 10) || 0;
      intervalMinutes = intervalUnit === 'HOURS' ? val * 60
        : intervalUnit === 'DAYS' ? val * 60 * 24 : val;
    }

    try {
      const geminiKey = sessionStorage.getItem('gemini_api_key') || '';
      const res = await fetch(`${API}/sast/schedule`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Gemini-Key': geminiKey },
        body: JSON.stringify({
          repo_url: repoUrl,
          target_name: repo.name,
          interval_minutes: intervalMinutes,
          ai_summary_level: aiLevel,
          scan_paths: paths,
        }),
      });
      if (res.ok) {
        const d = await res.json();
        setScanId(d.scan_id);
        setActiveTab('results');
        savePendingScan(d.scan_id, repoName, owner);
      } else {
        setScanStatus('ERROR');
      }
    } catch {
      setScanStatus('ERROR');
    }
  };

  const handleGenerateReport = async () => {
    if (!scanData) return;
    setIsGeneratingPdf(true);
    try {
      const res = await fetch(`${API}/reports/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: `Conformidade ${aiLevel} — ${repo.name}`,
          target: `repo:${repo.name}`,
          target_label: repo.name,
          type: 'Scan de Repositório',
          standard: aiLevel === 'CONFORMIDADE' ? 'ISO 27001 / SOC2' : 'OWASP Top 10',
          risk: scanData.vulnerable ? 'HIGH' : 'CLEAN',
          compliance_model: aiLevel,
          scan_data: scanData.scanner_results,
        }),
      });
      showToast(res.ok
        ? 'Relatório salvo! Acesse a aba Relatórios para exportar.'
        : 'Erro ao salvar relatório.');
    } catch { showToast('Erro ao salvar relatório.'); }
    setIsGeneratingPdf(false);
  };

  const handleAiInsights = async () => {
    const geminiKey = sessionStorage.getItem('gemini_api_key') || localStorage.getItem('previswit_gemini_key') || '';
    if (!geminiKey) {
      showToast('Configure a chave Gemini em Integrações para usar IA Insights.');
      return;
    }
    setAiInsightsLoading(true);
    setAiInsightsText('');

    try {
      // Usa validate-sast (gemini-2.5-flash, retry automático) em vez de ai/insight (gemini-2.0-flash)
      const res = await fetch(`${API}/ai/validate-sast`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Gemini-Key': geminiKey },
        body: JSON.stringify({
          sha: scanData.sha || 'sast-repo-scan',
          message: `Análise SAST — ${repo.name}`,
          author: owner,
          date: scanData.analyzed_at || new Date().toISOString(),
          scanner_results: scanData.scanner_results || {},
          files: [],
          executive_mode: false,
        }),
      });
      if (res.ok) {
        const d = await res.json();
        setAiInsightsText(d.analysis || '');
        setShowFindings(true);
      } else if (res.status === 401) {
        showToast('Configure a chave Gemini em Integrações para usar IA Insights.');
      } else {
        const err = await res.json().catch(() => ({}));
        showToast(err.detail || 'Erro ao consultar IA. Tente novamente.');
      }
    } catch {
      showToast('Erro de conexão com o servidor.');
    }
    setAiInsightsLoading(false);
  };

  const togglePath = (path) => {
    setSelectedPaths(prev => {
      const next = new Set(prev);
      next.has(path) ? next.delete(path) : next.add(path);
      return next;
    });
  };

  const addCustomPath = () => {
    const v = customInput.trim();
    if (v && !customPaths.includes(v)) {
      setCustomPaths(prev => [...prev, v]);
      setCustomInput('');
    }
  };

  const isScanning = scanStatus === 'PENDING' || scanStatus === 'RUNNING';
  const counts = scanData?.counts || {};
  const toolErrors = scanData?.tool_errors || {};
  const hasResults = scanStatus === 'CONCLUÍDO' && scanData;

  // ── Render ──────────────────────────────────────────────────────────────────
  return (
    <div className="fixed inset-0 z-[200] bg-[#030508] flex flex-col">

      {/* ── Top bar ──────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-white/[0.06] bg-[#060b13] shrink-0">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-purple-500/10 border border-purple-500/20">
            <Terminal className="w-5 h-5 text-purple-400" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white">Análise SAST</h2>
            <p className="text-[11px] text-gray-500 mt-0.5">{repo.name}</p>
          </div>
          {repo.language && (
            <span className="hidden sm:flex items-center gap-1.5 text-[11px] text-gray-500 bg-white/[0.04] border border-white/[0.06] rounded-lg px-2.5 py-1 ml-2">
              <span className="w-2 h-2 rounded-full" style={{ backgroundColor: langColor(repo.language) }} />
              {repo.language}
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          {/* Tab switcher */}
          <div className="flex gap-1 bg-white/[0.04] rounded-lg p-1">
            <button
              onClick={() => setActiveTab('config')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-all ${activeTab === 'config' ? 'bg-purple-600 text-white shadow-lg shadow-purple-600/20' : 'text-gray-400 hover:text-white'}`}
            >
              <Settings className="w-3 h-3 inline mr-1" />
              Configurar
            </button>
            <button
              onClick={() => setActiveTab('results')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-all relative ${activeTab === 'results' ? 'bg-purple-600 text-white shadow-lg shadow-purple-600/20' : 'text-gray-400 hover:text-white'}`}
            >
              <Shield className="w-3 h-3 inline mr-1" />
              Resultados
              {isScanning && (
                <span className="absolute -top-0.5 -right-0.5 w-2 h-2 bg-blue-400 rounded-full animate-pulse" />
              )}
              {hasResults && scanData.vulnerable && (
                <span className="absolute -top-0.5 -right-0.5 w-2 h-2 bg-red-400 rounded-full" />
              )}
            </button>
          </div>
          <button onClick={onClose}
            className="p-2 rounded-lg text-gray-500 hover:text-white hover:bg-white/[0.06] transition-all">
            <X className="w-5 h-5" />
          </button>
        </div>
      </div>

      {/* ── Body ─────────────────────────────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto">

        {/* ===== CONFIG TAB ===== */}
        {activeTab === 'config' && (
          <div className="max-w-2xl mx-auto px-6 py-8 flex flex-col gap-8">

            {/* Scope selector */}
            <div>
              <p className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-3">
                Escopo da Varredura
              </p>
              <div className="grid grid-cols-2 gap-3">
                {[
                  { value: 'full', icon: <Server className="w-4 h-4" />, label: 'Análise Completa', hint: 'Varre todo o repositório' },
                  { value: 'specific', icon: <Folder className="w-4 h-4" />, label: 'Pastas / Arquivos', hint: 'Escolha o que analisar' },
                ].map(opt => (
                  <button key={opt.value} onClick={() => setScope(opt.value)}
                    className={`flex items-start gap-3 p-4 rounded-xl border text-left transition-all duration-150 ${
                      scope === opt.value
                        ? 'border-purple-500/50 bg-purple-500/10 text-white'
                        : 'border-white/[0.06] bg-white/[0.02] text-gray-400 hover:border-white/15'
                    }`}>
                    <span className={scope === opt.value ? 'text-purple-400' : ''}>{opt.icon}</span>
                    <div>
                      <p className="text-xs font-semibold">{opt.label}</p>
                      <p className="text-[10px] text-gray-500 mt-0.5">{opt.hint}</p>
                    </div>
                  </button>
                ))}
              </div>

              {/* File tree picker */}
              {scope === 'specific' && (
                <div className="mt-4 space-y-3">
                  <p className="text-[11px] text-gray-500">
                    Selecione na árvore do repositório ou adicione caminhos manualmente:
                  </p>

                  {/* Tree from GitHub */}
                  <div className="bg-[#0d1421] border border-white/[0.06] rounded-xl overflow-hidden">
                    <div className="px-3 py-2 border-b border-white/[0.05] flex items-center justify-between">
                      <p className="text-[10px] text-gray-500 font-medium uppercase tracking-wider">
                        Raiz do Repositório
                      </p>
                      <button onClick={fetchRepoTree}
                        className="text-[10px] text-gray-600 hover:text-gray-400 flex items-center gap-1">
                        <RefreshCw className={`w-3 h-3 ${loadingTree ? 'animate-spin' : ''}`} />
                        Atualizar
                      </button>
                    </div>
                    <div className="max-h-52 overflow-y-auto divide-y divide-white/[0.04]">
                      {loadingTree ? (
                        <div className="flex items-center justify-center py-8">
                          <div className="w-4 h-4 border-2 border-purple-500 border-t-transparent rounded-full animate-spin" />
                        </div>
                      ) : repoTree.length === 0 ? (
                        <p className="text-[11px] text-gray-600 text-center py-6">
                          Nenhum arquivo encontrado — verifique o token GitHub
                        </p>
                      ) : repoTree.map(item => {
                        const checked = selectedPaths.has(item.path);
                        return (
                          <button key={item.path}
                            onClick={() => togglePath(item.path)}
                            className={`w-full flex items-center gap-2.5 px-3 py-2.5 text-left transition-colors text-xs ${
                              checked ? 'bg-purple-500/10 text-purple-300' : 'text-gray-400 hover:bg-white/[0.03]'
                            }`}>
                            <div className={`w-3.5 h-3.5 rounded border flex items-center justify-center shrink-0 ${
                              checked ? 'bg-purple-600 border-purple-500' : 'border-white/20'
                            }`}>
                              {checked && <CheckCircle className="w-2.5 h-2.5 text-white" />}
                            </div>
                            {item.type === 'dir'
                              ? <Folder className="w-3.5 h-3.5 text-amber-400/70 shrink-0" />
                              : <File className="w-3.5 h-3.5 text-blue-400/70 shrink-0" />
                            }
                            <span className="truncate">{item.name}</span>
                            {item.type === 'dir' && <span className="ml-auto text-[9px] text-gray-600">pasta</span>}
                          </button>
                        );
                      })}
                    </div>
                  </div>

                  {/* Selected chips */}
                  {(selectedPaths.size > 0 || customPaths.length > 0) && (
                    <div className="flex flex-wrap gap-1.5">
                      {[...selectedPaths].map(p => (
                        <span key={p}
                          className="flex items-center gap-1 text-[10px] bg-purple-500/15 text-purple-300 border border-purple-500/25 rounded-full px-2 py-0.5">
                          {p}
                          <button onClick={() => togglePath(p)}>
                            <X className="w-2.5 h-2.5 hover:text-white" />
                          </button>
                        </span>
                      ))}
                      {customPaths.map(p => (
                        <span key={p}
                          className="flex items-center gap-1 text-[10px] bg-blue-500/15 text-blue-300 border border-blue-500/25 rounded-full px-2 py-0.5">
                          {p}
                          <button onClick={() => setCustomPaths(prev => prev.filter(x => x !== p))}>
                            <X className="w-2.5 h-2.5 hover:text-white" />
                          </button>
                        </span>
                      ))}
                    </div>
                  )}

                  {/* Manual path input */}
                  <div className="flex gap-2">
                    <input
                      value={customInput}
                      onChange={e => setCustomInput(e.target.value)}
                      onKeyDown={e => e.key === 'Enter' && addCustomPath()}
                      placeholder="Caminho manual, ex: src/api/"
                      className="flex-1 bg-[#111827] border border-white/10 rounded-lg px-3 py-2 text-xs text-white placeholder:text-gray-600 focus:outline-none focus:border-purple-500/50"
                    />
                    <button onClick={addCustomPath}
                      className="px-3 py-2 rounded-lg bg-white/[0.06] border border-white/10 text-gray-400 hover:text-white hover:bg-white/10 transition-all">
                      <Plus className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              )}
            </div>

            {/* AI level */}
            <div>
              <p className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-3">
                Foco da Inteligência Artificial
              </p>
              <div className="grid grid-cols-1 gap-2.5">
                {[
                  { v: 'EXECUTIVO', emoji: '📊', label: 'Visão Executiva', hint: 'Riscos de negócio, conformidade regulatória e impactos estratégicos.' },
                  { v: 'TECNICO', emoji: '⚙️', label: 'Visão Técnica', hint: 'Falhas no código, CWEs/OWASP e instruções de refatoração.' },
                  { v: 'CONFORMIDADE', emoji: '🛡️', label: 'Visão de Conformidade', hint: 'Mapeia achados para controles ISO 27001 e SOC2.' },
                ].map(opt => (
                  <button key={opt.v} onClick={() => setAiLevel(opt.v)}
                    className={`flex items-start gap-3 p-3.5 rounded-xl border text-left transition-all duration-150 ${
                      aiLevel === opt.v
                        ? 'border-purple-500/50 bg-purple-500/10 text-white'
                        : 'border-white/[0.06] bg-white/[0.02] text-gray-400 hover:border-white/15'
                    }`}>
                    <span className="text-base shrink-0 mt-0.5">{opt.emoji}</span>
                    <div>
                      <p className="text-xs font-semibold">{opt.label}</p>
                      <p className="text-[10px] text-gray-500 mt-0.5 leading-relaxed">{opt.hint}</p>
                    </div>
                  </button>
                ))}
              </div>
            </div>

            {/* Frequency */}
            <div>
              <p className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-3">
                Frequência de Varredura
              </p>
              <div className="flex items-center justify-between p-3 bg-white/[0.03] border border-white/[0.06] rounded-xl">
                <span className="text-xs text-gray-300">Rodar apenas uma vez agora</span>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input type="checkbox" checked={runOnce}
                    onChange={e => setRunOnce(e.target.checked)} className="sr-only peer" />
                  <div className="w-9 h-5 bg-white/10 peer-focus:ring-2 peer-focus:ring-purple-500/50 rounded-full peer peer-checked:after:translate-x-4 after:absolute after:top-0.5 after:left-0.5 after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-purple-600" />
                </label>
              </div>
              {!runOnce && (
                <div className="flex gap-2 mt-3">
                  <input type="number" placeholder="Ex: 30" value={intervalValue}
                    onChange={e => setIntervalValue(e.target.value)}
                    className="flex-1 bg-[#111827] border border-white/10 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-purple-500/50" />
                  <select value={intervalUnit} onChange={e => setIntervalUnit(e.target.value)}
                    className="w-1/3 bg-[#111827] border border-white/10 rounded-lg px-3 py-2 text-xs text-white focus:outline-none">
                    <option value="MINUTES">Minutos</option>
                    <option value="HOURS">Horas</option>
                    <option value="DAYS">Dias</option>
                  </select>
                </div>
              )}
            </div>

            {/* Start button */}
            <button onClick={handleStartScan} disabled={isScanning}
              className="w-full py-3 rounded-xl bg-purple-600 hover:bg-purple-500 text-white text-sm font-semibold
                         shadow-lg shadow-purple-600/20 transition-all disabled:opacity-50 disabled:cursor-not-allowed
                         flex items-center justify-center gap-2">
              {isScanning ? (
                <><span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />Analisando…</>
              ) : (
                <><Terminal className="w-4 h-4" />Iniciar Scan SAST</>
              )}
            </button>
          </div>
        )}

        {/* ===== RESULTS TAB ===== */}
        {activeTab === 'results' && (
          <div className="max-w-2xl mx-auto px-6 py-8 flex flex-col gap-6">

            {/* Scanning progress */}
            {isScanning && (
              <div className="flex flex-col items-center justify-center py-16 gap-5">
                <div className="relative">
                  <div className="w-16 h-16 rounded-full border-2 border-purple-500/20" />
                  <div className="w-16 h-16 rounded-full border-2 border-purple-500 border-t-transparent animate-spin absolute inset-0" />
                  <Terminal className="w-6 h-6 text-purple-400 absolute inset-0 m-auto" />
                </div>
                <div className="text-center">
                  <p className="text-sm font-semibold text-white">Varredura em andamento…</p>
                  <p className="text-xs text-gray-500 mt-1">
                    {scope === 'full'
                      ? 'Semgrep · Trivy · Gitleaks · Checkov'
                      : `Escopo: ${[...selectedPaths, ...customPaths].join(', ') || 'completo'}`}
                  </p>
                </div>
                <div className="flex gap-2">
                  {['Semgrep', 'Trivy', 'Gitleaks', 'Checkov'].map(t => (
                    <span key={t} className="text-[10px] bg-white/[0.04] border border-white/[0.06] text-gray-500 rounded-full px-2.5 py-1 animate-pulse">
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* No results yet */}
            {!isScanning && !hasResults && (
              <div className="flex flex-col items-center justify-center py-16 gap-4">
                <div className="p-5 rounded-2xl bg-white/[0.03] border border-white/[0.06]">
                  <Shield className="w-8 h-8 text-gray-600" />
                </div>
                <p className="text-sm text-gray-500">Nenhuma análise executada ainda.</p>
                <button onClick={() => setActiveTab('config')}
                  className="text-xs text-purple-400 hover:text-purple-300 underline underline-offset-2">
                  Configurar e iniciar scan
                </button>
              </div>
            )}

            {/* Results */}
            {hasResults && (
              <>
                {/* Status banner */}
                <div className={`flex items-center gap-4 p-4 rounded-xl border ${
                  scanData.vulnerable
                    ? 'bg-red-500/10 border-red-500/25'
                    : 'bg-emerald-500/10 border-emerald-500/25'
                }`}>
                  {scanData.vulnerable
                    ? <AlertOctagon className="w-8 h-8 text-red-400 shrink-0" />
                    : <CheckCircle className="w-8 h-8 text-emerald-400 shrink-0" />
                  }
                  <div className="flex-1">
                    <p className={`text-sm font-bold ${scanData.vulnerable ? 'text-red-300' : 'text-emerald-300'}`}>
                      {scanData.vulnerable ? '⚠️ Vulnerabilidades Detectadas' : '🛡️ Código Seguro'}
                    </p>
                    <p className="text-[11px] text-gray-400 mt-0.5">
                      Analisado em {scanData.analyzed_at
                        ? new Date(scanData.analyzed_at).toLocaleString('pt-BR')
                        : '—'}
                      {scanData.scanned_paths?.length > 0 && (
                        <> · Escopo: {scanData.scanned_paths.join(', ')}</>
                      )}
                    </p>
                  </div>
                  {scanData.scan_status && (
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border uppercase ${
                      scanData.scan_status === 'OK' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/25' :
                      scanData.scan_status === 'PARTIAL' ? 'bg-amber-500/10 text-amber-400 border-amber-500/25' :
                      'bg-red-500/10 text-red-400 border-red-500/25'
                    }`}>
                      {scanData.scan_status}
                    </span>
                  )}
                </div>

                {/* Tool cards */}
                <div className="grid grid-cols-2 gap-3">
                  {[
                    { key: 'semgrep',  label: 'Semgrep',  icon: <Code2 className="w-4 h-4" />,  color: 'text-purple-400', bg: 'bg-purple-500/10 border-purple-500/20', desc: 'SAST / AST' },
                    { key: 'trivy',    label: 'Trivy',    icon: <Bug className="w-4 h-4" />,     color: 'text-sky-400',    bg: 'bg-sky-500/10 border-sky-500/20',       desc: 'CVEs / Deps' },
                    { key: 'gitleaks', label: 'Gitleaks', icon: <Lock className="w-4 h-4" />,   color: 'text-rose-400',   bg: 'bg-rose-500/10 border-rose-500/20',     desc: 'Secrets' },
                    { key: 'checkov',  label: 'Checkov',  icon: <Server className="w-4 h-4" />, color: 'text-amber-400',  bg: 'bg-amber-500/10 border-amber-500/20',   desc: 'IaC' },
                  ].map(tool => {
                    const count = counts[tool.key] ?? 0;
                    const err = toolErrors[tool.key];
                    return (
                      <div key={tool.key} className={`rounded-xl border p-4 ${tool.bg}`}>
                        <div className="flex items-center justify-between mb-2">
                          <div className={`flex items-center gap-1.5 ${tool.color}`}>
                            {tool.icon}
                            <span className="text-xs font-semibold">{tool.label}</span>
                          </div>
                          <span className="text-[10px] text-gray-500">{tool.desc}</span>
                        </div>
                        {err ? (
                          <p className="text-[10px] text-red-400 flex items-center gap-1">
                            <AlertTriangle className="w-3 h-3" />{err}
                          </p>
                        ) : (
                          <p className={`text-2xl font-bold ${count > 0 ? tool.color : 'text-gray-500'}`}>
                            {count}
                            <span className="text-[10px] font-normal text-gray-500 ml-1">
                              {count === 1 ? 'achado' : 'achados'}
                            </span>
                          </p>
                        )}
                      </div>
                    );
                  })}
                </div>

                {/* ── Achados Detalhados ──────────────────────────────── */}
                {(() => {
                  const findings = extractFindings(scanData.scanner_results);
                  if (!findings.length) return null;
                  const TC = {
                    semgrep:  { text: 'text-purple-400', bg: 'bg-purple-500/10', border: 'border-purple-500/20' },
                    trivy:    { text: 'text-sky-400',    bg: 'bg-sky-500/10',    border: 'border-sky-500/20' },
                    gitleaks: { text: 'text-rose-400',   bg: 'bg-rose-500/10',   border: 'border-rose-500/20' },
                    checkov:  { text: 'text-amber-400',  bg: 'bg-amber-500/10',  border: 'border-amber-500/20' },
                  };
                  const SC = {
                    CRITICAL: 'text-rose-400 bg-rose-500/15 border-rose-500/30',
                    HIGH:     'text-red-400 bg-red-500/15 border-red-500/25',
                    MEDIUM:   'text-amber-400 bg-amber-500/15 border-amber-500/25',
                    LOW:      'text-blue-400 bg-blue-500/15 border-blue-500/25',
                  };
                  return (
                    <div className="rounded-xl border border-white/[0.07] overflow-hidden">
                      <button
                        onClick={() => setShowFindings(p => !p)}
                        className="w-full flex items-center justify-between px-4 py-3 bg-white/[0.03] hover:bg-white/[0.05] transition-colors"
                      >
                        <div className="flex items-center gap-2">
                          <Bug className="w-4 h-4 text-red-400" />
                          <span className="text-xs font-semibold text-white">Achados Detalhados</span>
                          <span className="text-[10px] bg-red-500/15 text-red-400 border border-red-500/25 rounded-full px-2 py-0.5">
                            {findings.length} {findings.length === 1 ? 'achado' : 'achados'} HIGH/CRITICAL
                          </span>
                        </div>
                        <ChevronDown className={`w-4 h-4 text-gray-500 transition-transform duration-200 ${showFindings ? 'rotate-180' : ''}`} />
                      </button>

                      {showFindings && (
                        <div className="divide-y divide-white/[0.04]">
                          {findings.map((f, i) => {
                            const tc = TC[f.tool] || TC.checkov;
                            const sc = SC[f.severity] || SC.LOW;
                            return (
                              <div key={i} className="px-4 py-3.5 hover:bg-white/[0.02] transition-colors">
                                <div className="flex items-start gap-2.5">
                                  <span className={`shrink-0 text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border mt-0.5 ${tc.bg} ${tc.text} ${tc.border}`}>
                                    {f.tool}
                                  </span>
                                  <div className="flex-1 min-w-0">
                                    <div className="flex items-center gap-2 flex-wrap">
                                      <span className="text-[11px] font-mono font-semibold text-gray-200">
                                        {f.ruleId}
                                      </span>
                                      <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded border ${sc}`}>
                                        {f.severity}
                                      </span>
                                    </div>
                                    <p className="text-[10px] text-gray-500 font-mono mt-0.5 truncate">
                                      📄 {f.file}{f.line ? `:${f.line}${f.lineEnd && f.lineEnd !== f.line ? `–${f.lineEnd}` : ''}` : ''}
                                    </p>
                                    <p className="text-[11px] text-gray-300 mt-1 leading-relaxed">{f.message}</p>
                                    {f.pkg && (
                                      <p className="text-[10px] text-gray-600 mt-0.5">
                                        Pacote: <span className="text-gray-400 font-mono">{f.pkg}</span> {f.installed}
                                        {f.fixed && <> → <span className="text-emerald-400 font-mono">corrigido: {f.fixed}</span></>}
                                      </p>
                                    )}
                                    {f.resource && (
                                      <p className="text-[10px] text-gray-600 mt-0.5">
                                        Recurso: <span className="text-gray-400 font-mono">{f.resource}</span>
                                      </p>
                                    )}
                                    {f.match && (
                                      <p className="text-[10px] text-rose-400/70 font-mono mt-0.5 break-all">{f.match}</p>
                                    )}
                                  </div>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  );
                })()}

                {/* ── IA Insights ─────────────────────────────────────── */}
                {scanData.vulnerable && (
                  <div className="rounded-xl border border-indigo-500/20 overflow-hidden">
                    <div className="px-4 py-3 bg-indigo-500/[0.06] flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <BrainCircuit className="w-4 h-4 text-indigo-400" />
                        <span className="text-xs font-semibold text-white">IA Insights</span>
                        <span className="text-[10px] text-indigo-400/60">Análise técnica por achado</span>
                      </div>
                      <button
                        onClick={handleAiInsights}
                        disabled={aiInsightsLoading}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold
                                   bg-indigo-600 hover:bg-indigo-500 text-white transition-all
                                   disabled:opacity-50 disabled:cursor-not-allowed shadow-lg shadow-indigo-500/20"
                      >
                        {aiInsightsLoading
                          ? <><span className="w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin" />Analisando…</>
                          : <><Sparkles className="w-3 h-3" />Analisar com IA</>
                        }
                      </button>
                    </div>
                    {aiInsightsText ? (
                      <div className="px-5 py-4 border-t border-indigo-500/10">
                        <p className="text-[12px] text-gray-300 leading-relaxed whitespace-pre-line">
                          {aiInsightsText}
                        </p>
                      </div>
                    ) : (
                      !aiInsightsLoading && (
                        <div className="px-4 py-4 border-t border-white/[0.04]">
                          <p className="text-[11px] text-gray-600 text-center">
                            Clique em "Analisar com IA" — a Gemini vai dizer se cada achado é real, onde está no código e como remediar.
                          </p>
                        </div>
                      )
                    )}
                    {aiInsightsLoading && (
                      <div className="px-4 py-6 border-t border-white/[0.04] flex items-center justify-center gap-2">
                        <span className="w-4 h-4 border-2 border-indigo-400 border-t-transparent rounded-full animate-spin" />
                        <span className="text-xs text-gray-500">Gemini está analisando os achados…</span>
                      </div>
                    )}
                  </div>
                )}

                {/* AI Insight summary (from scan) */}
                {scanData.ai_insight && (
                  <div className="bg-white/[0.03] border border-white/[0.06] rounded-xl p-4">
                    <p className="text-[10px] text-purple-400 uppercase tracking-wider font-semibold mb-2 flex items-center gap-1.5">
                      <Zap className="w-3 h-3" />Resumo IA — {aiLevel}
                    </p>
                    <p className="text-[12px] text-gray-300 leading-relaxed whitespace-pre-line">
                      {scanData.ai_insight}
                    </p>
                  </div>
                )}

                {/* CVE count */}
                {scanData.cve_report?.total > 0 && (
                  <div className="flex items-center gap-3 p-3 bg-orange-500/10 border border-orange-500/20 rounded-xl">
                    <Info className="w-4 h-4 text-orange-400 shrink-0" />
                    <p className="text-xs text-orange-300">
                      <strong>{scanData.cve_report.unique_cve_ids?.length || 0} CVEs</strong> identificados
                      ({scanData.cve_report.osv_enriched_count || 0} enriquecidos via OSV.dev)
                    </p>
                  </div>
                )}

                {/* Tool errors (partial) */}
                {Object.keys(toolErrors).length > 0 && (
                  <div className="bg-amber-500/10 border border-amber-500/20 rounded-xl p-3">
                    <p className="text-[10px] text-amber-400 font-semibold uppercase tracking-wider mb-1.5">
                      Ferramentas com falha
                    </p>
                    <div className="space-y-1">
                      {Object.entries(toolErrors).map(([t, e]) => (
                        <p key={t} className="text-[11px] text-gray-400">
                          <span className="text-amber-300 font-medium">{t}</span>: {e}
                        </p>
                      ))}
                    </div>
                  </div>
                )}

                {/* Generate report */}
                <button
                  onClick={handleGenerateReport}
                  disabled={isGeneratingPdf}
                  className="w-full flex items-center justify-center gap-2 py-3 rounded-xl
                             border border-white/[0.08] bg-white/[0.03] text-gray-300 text-sm font-medium
                             hover:bg-white/[0.07] hover:text-white hover:border-white/15 transition-all
                             disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  {isGeneratingPdf
                    ? <><RefreshCw className="w-4 h-4 animate-spin" />Salvando…</>
                    : <><FileText className="w-4 h-4" />Gerar Relatório de Conformidade</>
                  }
                </button>
              </>
            )}
          </div>
        )}
      </div>

      {/* Toast */}
      {toast && (
        <div className="fixed bottom-6 right-6 z-[300] flex items-center gap-2 px-4 py-3 rounded-xl
                        shadow-2xl border border-purple-500/30 bg-[#0d1421]/95 backdrop-blur-md
                        text-xs font-medium text-purple-200 animate-in slide-in-from-bottom-2">
          <CheckCircle className="w-4 h-4 text-purple-400 shrink-0" />
          {toast}
        </div>
      )}
    </div>
  );
}

// ── Repository Card ───────────────────────────────────────────────────────────

function RepositoryCard({ repo, onOpenPanel, openRiskGraph }) {
  const slug = repo.name?.toLowerCase().replace(/[^a-z0-9]/g, '-') ?? 'repo';

  const effectiveScanData = repo.scanner_results;
  const repoShortName = repo.name?.split('/').pop() || repo.name;

  let badgeProps = { bg: 'bg-amber-500/10', border: 'border-amber-500/30', text: 'text-amber-400', label: '⏳ Aguardando Scan' };
  if (effectiveScanData) {
    const isVuln = effectiveScanData.vulnerable === true ||
      (effectiveScanData.vulnerable !== false && effectiveScanData.clean === false);
    if (effectiveScanData.vulnerable === false || effectiveScanData.clean === true) {
      badgeProps = { bg: 'bg-emerald-500/10', border: 'border-emerald-500/30', text: 'text-emerald-400', label: '🛡️ Código Seguro' };
    } else if (isVuln) {
      badgeProps = { bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-400', label: `⚠️ Risco: ${effectiveScanData.severity || 'HIGH'}` };
    } else {
      badgeProps = { bg: 'bg-emerald-500/10', border: 'border-emerald-500/30', text: 'text-emerald-400', label: '🛡️ Código Seguro' };
    }
  }

  return (
    <div className="group relative flex flex-col rounded-2xl border border-white/[0.06] bg-gradient-to-b from-[#0d1421]/80 to-[#060b13]/90
                   hover:border-purple-500/25 hover:shadow-xl hover:shadow-purple-500/5 transition-all duration-300 overflow-hidden">
      <div className={`h-[2px] w-full ${
        badgeProps.text === 'text-emerald-400' ? 'bg-gradient-to-r from-emerald-500/60 to-teal-500/40' :
        badgeProps.text === 'text-red-400' ? 'bg-gradient-to-r from-red-500/60 to-orange-500/40' :
        'bg-gradient-to-r from-white/5 to-white/0'}`} />

      <div className="flex flex-col gap-4 p-5 flex-1">
        {/* Header */}
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-3 min-w-0">
            <div className="shrink-0 w-9 h-9 flex items-center justify-center rounded-xl border bg-purple-500/10 border-purple-500/20">
              <GitBranch className="w-4 h-4 text-purple-400" />
            </div>
            <div className="min-w-0">
              <p className="text-sm font-bold text-white truncate group-hover:text-purple-100 transition-colors" title={repo.name}>
                {repoShortName}
              </p>
              {repo.name?.includes('/') && (
                <p className="text-[10px] text-gray-600 truncate mt-0.5">{repo.name}</p>
              )}
            </div>
          </div>
          <span className={`shrink-0 text-[10px] font-bold px-2.5 py-1 rounded-full border ${badgeProps.bg} ${badgeProps.text} ${badgeProps.border} whitespace-nowrap`}>
            {badgeProps.label}
          </span>
        </div>

        {/* Meta */}
        <div className="flex items-center gap-3">
          {repo.language && (
            <div className="flex items-center gap-1.5 bg-white/[0.04] border border-white/[0.06] rounded-lg px-2.5 py-1">
              <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: langColor(repo.language) }} />
              <span className="text-[11px] font-medium text-gray-400">{repo.language}</span>
            </div>
          )}
          <div className="flex items-center gap-1.5 text-[11px] text-gray-600 ml-auto">
            <Clock className="w-3 h-3" />{fmtDate(repo.updated_at)}
          </div>
        </div>

        {/* AI insight preview */}
        {effectiveScanData?.ai_insight && (
          <div className="bg-white/[0.03] border border-white/[0.05] rounded-xl p-3">
            <p className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold mb-1.5 flex items-center gap-1.5">
              <Zap className="w-3 h-3 text-purple-400" />AI Insight
            </p>
            <p className="text-[11px] text-gray-400 leading-relaxed line-clamp-2">
              {effectiveScanData.ai_insight}
            </p>
          </div>
        )}

        <div className="border-t border-white/[0.04] -mx-5" />

        {/* Actions */}
        <div className="flex gap-2">
          <button
            onClick={() => onOpenPanel(repo)}
            className="flex-1 flex items-center justify-center gap-1.5 py-2 text-xs font-semibold
                       rounded-xl border border-purple-500/25 text-purple-400
                       hover:bg-purple-500/10 hover:border-purple-500/40 hover:text-purple-300 transition-all"
          >
            <Terminal className="w-3 h-3" />Scan SAST
          </button>
          <button
            onClick={() => openRiskGraph(repo)}
            className="flex-1 flex items-center justify-center gap-1.5 py-2 text-xs font-semibold
                       rounded-xl border border-teal-500/25 text-teal-400
                       hover:bg-teal-500/10 hover:border-teal-500/40 hover:text-teal-300 transition-all"
          >
            <Eye className="w-3 h-3" />Deep Dive
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Empty / Connect ───────────────────────────────────────────────────────────

function RepositoriesEmptyState({ onConnect }) {
  return (
    <div className="flex flex-col items-center justify-center p-16 mt-4 border border-dashed border-white/[0.06] rounded-2xl bg-gradient-to-b from-[#0d1421]/40 to-transparent">
      <div className="relative mb-6">
        <div className="w-16 h-16 rounded-2xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center">
          <GitBranch className="w-7 h-7 text-purple-400/60" />
        </div>
        <div className="absolute -bottom-1 -right-1 w-5 h-5 rounded-full bg-amber-500/20 border border-amber-500/30 flex items-center justify-center">
          <span className="text-[10px]">?</span>
        </div>
      </div>
      <p className="text-sm font-semibold text-gray-300 text-center">Nenhum repositório sincronizado</p>
      <p className="text-xs text-gray-600 text-center mt-2 max-w-xs leading-relaxed">
        Conecte sua conta do GitHub para importar sua base de código e iniciar os scans SAST.
      </p>
      <button onClick={onConnect}
        className="mt-6 flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold bg-purple-600 hover:bg-purple-500 text-white shadow-lg shadow-purple-500/25 transition-all">
        <Link2 className="w-4 h-4" />Conectar GitHub
      </button>
    </div>
  );
}

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
        <div className="flex items-center gap-3 mb-6">
          <div className="p-2.5 rounded-xl bg-purple-500/10 border border-purple-500/20">
            <Link2 className="w-5 h-5 text-purple-400" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-white">Conectar GitHub</h3>
            <p className="text-xs text-gray-500 mt-0.5">Personal Access Token (PAT)</p>
          </div>
        </div>
        <input id="github-token" type="password" placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
          value={tokenInput} onChange={e => setTokenInput(e.target.value)}
          className="w-full bg-[#111827] border border-white/10 rounded-lg px-3 py-2 text-sm text-white mb-1.5
                     focus:outline-none focus:border-purple-500/50 placeholder:text-gray-600" />
        <p className="text-[10px] text-gray-500 mb-5">
          Armazenado apenas na sessão do navegador, não enviado ao banco de dados.
        </p>
        <div className="flex gap-2">
          <button onClick={onClose}
            className="flex-1 py-2 rounded-lg border border-white/10 text-gray-400 text-sm hover:bg-white/5 transition-all">
            Cancelar
          </button>
          <button onClick={handleConnect} disabled={!tokenInput.trim()}
            className="flex-1 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-sm font-semibold shadow-lg shadow-purple-500/20 transition-all disabled:opacity-50">
            Conectar
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function RepositoriesPage() {
  const [repositories, setRepositories] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [lastSync, setLastSync] = useState(null);
  const [connectOpen, setConnectOpen] = useState(false);

  const [activeView, setActiveView] = useState('list');
  const [selectedRepo, setSelectedRepo] = useState(null);
  const [panelRepo, setPanelRepo] = useState(null);

  const openRiskGraph = useCallback((repo) => {
    setSelectedRepo(repo);
    setActiveView('canvas');
  }, []);

  const handleOpenPanel = useCallback((repo) => {
    setPanelRepo(repo);
  }, []);

  const handleScanComplete = useCallback((repoName, data) => {
    setRepositories(prev => prev.map(r =>
      r.name === repoName ? { ...r, scanner_results: data } : r,
    ));
  }, []);

  const fetchRepositories = useCallback(async () => {
    const token = sessionStorage.getItem('GITHUB_TOKEN');
    if (!token) { setRepositories([]); return; }
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API}/github/repos`, { headers: { 'X-GitHub-Token': token } });
      if (!res.ok) {
        if (res.status === 401) { sessionStorage.removeItem('GITHUB_TOKEN'); throw new Error("Token inválido."); }
        throw new Error(`HTTP ${res.status}`);
      }
      const data = await res.json();
      const fetched = data.repos ?? [];
      fetched.forEach(r => {
        const cached = localStorage.getItem('previswit_sast_current_view');
        if (cached) {
          try {
            const parsed = JSON.parse(cached);
            if (parsed.target === r.name) r.scanner_results = parsed.data;
          } catch {}
        }
      });
      setRepositories(fetched);
      setLastSync(new Date());
    } catch (err) {
      setError(err.message);
    }
    setLoading(false);
  }, []);

  useEffect(() => { fetchRepositories(); }, [fetchRepositories]);

  const scannedCount = repositories.filter(r => !!r.scanner_results).length;
  const langCount = new Set(repositories.map(r => r.language).filter(Boolean)).size;
  const pendingCount = repositories.length - scannedCount;

  if (activeView === 'canvas' && selectedRepo) {
    return <RiskGraphCanvas repo={selectedRepo} onBack={() => setActiveView('list')} />;
  }

  return (
    <>
      {panelRepo && (
        <SastScanPanel
          repo={panelRepo}
          onClose={() => setPanelRepo(null)}
          onScanComplete={handleScanComplete}
        />
      )}

      <ConnectModal open={connectOpen} onClose={() => setConnectOpen(false)} onConnectSuccess={fetchRepositories} />

      <section id="view-repositories" className="w-full flex flex-col gap-6">

        {/* Header */}
        <div className="flex items-start justify-between gap-4">
          <div className="flex flex-col gap-1">
            <div className="flex items-center gap-1.5">
              <NavLink to="/assets" className="text-xs text-gray-600 hover:text-gray-400 flex items-center gap-1 transition-colors">
                <ArrowLeft className="w-3 h-3" />Ativos &amp; Produtos
              </NavLink>
              <span className="text-gray-700">/</span>
              <span className="text-xs text-purple-400 font-medium">Repositórios</span>
            </div>
            <div>
              <h1 className="text-xl font-bold text-white flex items-center gap-2.5">
                <GitBranch className="w-5 h-5 text-purple-400" />Gestão de Repositórios
              </h1>
              <p className="text-sm text-gray-500 mt-0.5">Inventário de código-fonte · Análise SAST · Supply Chain Visibility</p>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {lastSync && (
              <div className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/[0.03] border border-white/[0.06]">
                <Activity className="w-3 h-3 text-emerald-400" />
                <span className="text-[11px] text-gray-500">Sync {lastSync.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })}</span>
              </div>
            )}
            <button onClick={fetchRepositories} disabled={loading}
              className="p-2 rounded-lg border border-white/[0.08] text-gray-500 hover:text-white hover:bg-white/5 hover:border-white/20 transition-all disabled:opacity-40">
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
            <button onClick={() => setConnectOpen(true)}
              className="flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold bg-purple-600 hover:bg-purple-500 text-white shadow-lg shadow-purple-500/20 transition-all">
              <Link2 className="w-4 h-4" />Conectar GitHub
            </button>
          </div>
        </div>

        {/* KPIs */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: 'Total de Repos', value: repositories.length, color: 'text-white', icon: <Database className="w-4 h-4 text-purple-400" />, sub: 'sincronizados', accent: 'border-purple-500/15' },
            { label: 'Scans Completos', value: scannedCount, color: 'text-emerald-400', icon: <Shield className="w-4 h-4 text-emerald-400" />, sub: 'analisados', accent: 'border-emerald-500/15' },
            { label: 'Linguagens', value: langCount, color: 'text-blue-400', icon: <Code2 className="w-4 h-4 text-blue-400" />, sub: 'detectadas', accent: 'border-blue-500/15' },
            { label: 'Aguardando Scan', value: pendingCount, color: 'text-amber-400', icon: <TrendingUp className="w-4 h-4 text-amber-400" />, sub: 'pendentes', accent: 'border-amber-500/15' },
          ].map(stat => (
            <div key={stat.label} className={`bg-gradient-to-b from-[#0d1421]/70 to-[#060b13]/60 border ${stat.accent} rounded-2xl p-4 flex items-center gap-3 transition-all`}>
              <div className="w-9 h-9 rounded-xl bg-white/[0.04] border border-white/[0.06] flex items-center justify-center shrink-0">
                {stat.icon}
              </div>
              <div>
                <p className="text-[10px] text-gray-600 uppercase tracking-wider font-semibold">{stat.label}</p>
                <p className={`text-2xl font-bold mt-0.5 ${stat.color} leading-none`}>{loading ? '—' : stat.value}</p>
                <p className="text-[10px] text-gray-700 mt-0.5">{stat.sub}</p>
              </div>
            </div>
          ))}
        </div>

        {/* Error */}
        {error && !loading && (
          <div className="flex items-center gap-3 px-4 py-3 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>Erro ao carregar repositórios: {error}</span>
            <button onClick={fetchRepositories} className="ml-auto text-xs underline">Tentar novamente</button>
          </div>
        )}

        {/* Loading */}
        {loading && (
          <div className="flex flex-col items-center justify-center py-20 gap-3">
            <div className="relative">
              <div className="w-8 h-8 border-2 border-purple-500/30 rounded-full" />
              <div className="w-8 h-8 border-2 border-purple-500 border-t-transparent rounded-full animate-spin absolute inset-0" />
            </div>
            <p className="text-sm text-gray-500">Sincronizando repositórios…</p>
          </div>
        )}

        {/* Grid */}
        {!loading && repositories.length > 0 && (
          <>
            <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider flex items-center gap-2">
              <span className="w-1 h-4 rounded-full bg-purple-500/60" />
              {repositories.length} repositório{repositories.length !== 1 ? 's' : ''} encontrado{repositories.length !== 1 ? 's' : ''}
            </h2>
            <div id="repositories-grid" className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
              {repositories.map((repo, idx) => (
                <RepositoryCard key={repo.name ?? idx} repo={repo}
                  onOpenPanel={handleOpenPanel} openRiskGraph={openRiskGraph} />
              ))}
            </div>
          </>
        )}

        {!loading && repositories.length === 0 && !error && (
          <RepositoriesEmptyState onConnect={() => setConnectOpen(true)} />
        )}

      </section>
    </>
  );
}
