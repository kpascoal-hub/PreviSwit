import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { ArrowLeft, GitCommit, User, Clock, ShieldAlert, ChevronRight, FileCode, BrainCircuit, Code, PlusCircle, MinusCircle, GitPullRequest, GripHorizontal, X, Trash2, Filter, Search, Shield, ShieldCheck, Zap, Send, Bot, FileText, Activity, MessageSquare } from 'lucide-react';

const API = '/api/v1';

export default function RiskGraphCanvas({ repo, onBack }) {
  const [commits, setCommits] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Pan & Zoom state
  const [transform, setTransform] = useState({ scale: 1, x: 0, y: 0 });
  const [isDraggingCanvas, setIsDraggingCanvas] = useState(false);
  const dragCanvasStart = useRef({ x: 0, y: 0 });
  const containerRef = useRef(null);

  // Dynamic Graph States
  const [openMenuSha, setOpenMenuSha] = useState(null);
  const [activeWidgets, setActiveWidgets] = useState({});
  const [branchData, setBranchData] = useState({});

  const [executiveSASTStep, setExecutiveSASTStep] = useState(0); // 0: None, 1: Choosing, 2: Typing Hash
  const [executiveSASTHash, setExecutiveSASTHash] = useState('');

  // Filters State
  const [isFilterOpen, setIsFilterOpen] = useState(false);
  const [draftFilters, setDraftFilters] = useState({ author: '', date: '', sort: 'desc' });
  const [activeFilters, setActiveFilters] = useState({ author: '', date: '', sort: 'desc' });

  // IDE Modal State
  const [selectedIDECommit, setSelectedIDECommit] = useState(null);
  const [selectedIDEFile, setSelectedIDEFile] = useState(null);
  const [ideLoading, setIdeLoading] = useState(false);

  // AI Copilot States
  const [isCopilotMenuOpen, setIsCopilotMenuOpen] = useState(false);
  const [isChatPanelOpen, setIsChatPanelOpen] = useState(false);
  const [chatMessages, setChatMessages] = useState([{ role: 'assistant', content: 'Olá! Sou seu **Copilot de Segurança**. O que vamos auditar hoje?' }]);
  const [chatInput, setChatInput] = useState('');
  const [isAiThinking, setIsAiThinking] = useState(false);
  const chatEndRef = useRef(null); // Ancora de auto-scroll

  // SAST Analysis States
  const [sastResults, setSastResults] = useState({});     // { [sha]: { vulnerable, severity, analysis, tools_used, loading } }
  const [fixedCommits, setFixedCommits] = useState({});   // { [sha]: true } — commits marcados como corrigidos
  const [fullSastData, setFullSastData] = useState(null); // Dados brutos do Quarteto para exibição técnica
  const [aiSummaries, setAiSummaries] = useState({});     // { [sha]: { loading, text } }

  // Node Drag & Drop State
  const [nodePositions, setNodePositions] = useState({});
  const maxZIndex = useRef(20);
  const dragNodeRef = useRef(null);

  // Constants
  const NODE_SPACING_Y = 220;
  const NODE_SPACING_X = 450;
  const PR_SPACING_X = 400;
  const START_X = 2500;
  const START_Y = 2500;

  // Initial Fetch
  useEffect(() => {
    async function fetchCommits() {
      const token = sessionStorage.getItem('GITHUB_TOKEN');
      if (!token) {
        setError("Token do GitHub não encontrado. Volte e conecte-se.");
        setLoading(false);
        return;
      }
      try {
        const res = await fetch(`${API}/github/repos/${repo.owner}/${repo.name}/commits`, {
          headers: { 'X-GitHub-Token': token }
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        
        // Hidratação do Estado via LocalStorage (Memória de Scan)
        const fetchedCommits = data.commits ?? [];
        const initialSast = {};
        
        fetchedCommits.forEach(c => {
          let cached = localStorage.getItem('previswit_scan_' + c.sha);
          
          if (!cached) {
            // A Herança de Fallback: Verifica se o repo pai já tem laudo
            const currentRepoId = repo.name;
            const parentRepoScan = localStorage.getItem('previswit_scan_' + currentRepoId);
            if (parentRepoScan) {
              try {
                const parsedParent = JSON.parse(parentRepoScan);
                const scannerRes = parsedParent.scanner_results || parsedParent;
                let commitVulns = [];
                
                Object.values(scannerRes).forEach(toolOut => {
                   if (Array.isArray(toolOut)) {
                     toolOut.forEach(v => { if (JSON.stringify(v).includes(c.sha)) commitVulns.push(v); });
                   } else if (toolOut && typeof toolOut === 'object') {
                     const results = toolOut.results || toolOut.Results || toolOut.Vulnerabilities || [];
                     if (Array.isArray(results)) {
                       results.forEach(v => { if (JSON.stringify(v).includes(c.sha)) commitVulns.push(v); });
                     }
                   }
                });
                
                if (commitVulns.length === 0) {
                  cached = JSON.stringify({ inherited: true, clean: true, vulnerabilities: [] });
                } else {
                  cached = JSON.stringify({ inherited: true, clean: false, vulnerabilities: commitVulns });
                }
              } catch (e) {}
            }
          }

          if (cached) {
            try {
              const parsed = JSON.parse(cached);

              // Formato novo: objeto com vulnerable/severity explícitos
              if (typeof parsed === 'object' && parsed !== null && 'vulnerable' in parsed) {
                c.scanner_results = parsed.scanner_results;
                initialSast[c.sha] = {
                  loading:         false,
                  analysis:        null,
                  vulnerable:      parsed.vulnerable === true,
                  severity:        parsed.severity || (parsed.vulnerable ? 'HIGH' : 'CLEAN'),
                  scan_status:     parsed.scan_status || 'OK',
                  scanner_results: parsed.scanner_results,
                };
              } else {
                // Formato legado: apenas scanner_results sem metadados
                const isVuln = parsed.inherited
                  ? parsed.clean === false
                  : Array.isArray(parsed) ? parsed.length > 0 : false;
                c.scanner_results = parsed;
                initialSast[c.sha] = {
                  loading: false, analysis: null,
                  vulnerable: isVuln, scanner_results: parsed,
                };
              }
            } catch (e) {
              console.error("Falha ao hidratar cache de scan do commit", c.sha);
            }
          }
        });
        
        if (Object.keys(initialSast).length > 0) {
          setSastResults(prev => ({ ...prev, ...initialSast }));
        }
        
        setCommits(fetchedCommits);

        if (containerRef.current) {
          const viewportWidth = containerRef.current.clientWidth;
          const viewportHeight = containerRef.current.clientHeight;
          setTransform({
            scale: 1,
            x: viewportWidth / 2 - START_X,
            y: viewportHeight / 2 - START_Y
          });
        }
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }
    if (repo && repo.owner) fetchCommits();
  }, [repo]);

  // Compute Layout Positions (Only for new elements)
  useEffect(() => {
    if (commits.length === 0) return;
    setNodePositions(prev => {
      const newPos = { ...prev };
      let prOffsetAccumulator = PR_SPACING_X;
      const mainCommits = commits.filter(c => !c.is_pending_auth);

      commits.forEach(commit => {
        let x, y;
        const isMain = !commit.is_pending_auth;
        const mainIdx = mainCommits.findIndex(c => c.sha === commit.sha);

        if (!newPos[commit.sha]) {
          if (isMain) {
            x = START_X;
            y = START_Y + mainIdx * NODE_SPACING_Y;
          } else {
            const baseIdx = mainCommits.findIndex(c => c.sha === commit.base_sha);
            const baseY = baseIdx !== -1 ? START_Y + baseIdx * NODE_SPACING_Y : START_Y + (mainCommits.length > 0 ? (mainCommits.length - 1) * NODE_SPACING_Y : 0);
            y = baseY + NODE_SPACING_Y / 2;
            x = START_X + prOffsetAccumulator;
            prOffsetAccumulator = prOffsetAccumulator > 0 ? -prOffsetAccumulator : (-prOffsetAccumulator) + PR_SPACING_X;
          }
          newPos[commit.sha] = { x, y, zIndex: 10, isMain, nextMainSha: isMain && mainIdx < mainCommits.length - 1 ? mainCommits[mainIdx + 1].sha : null };
        }

        const widgets = activeWidgets[commit.sha] || [];
        widgets.forEach((widget, wIdx) => {
          const widgetId = `${commit.sha}-${widget}`;
          if (!newPos[widgetId]) {
            let offsetY = 0;
            if (widgets.length === 2) offsetY = wIdx === 0 ? -350 : 350;
            if (widgets.length === 3) {
              if (wIdx === 0) offsetY = -350;
              if (wIdx === 1) offsetY = 0;
              if (wIdx === 2) offsetY = 350;
            }
            const parentPos = newPos[commit.sha];
            newPos[widgetId] = {
              x: parentPos.x + NODE_SPACING_X,
              y: parentPos.y + offsetY,
              zIndex: 15
            };
          }
        });
      });
      return newPos;
    });
  }, [commits, activeWidgets]);

  const toggleWidget = async (sha, widgetName) => {
    setOpenMenuSha(null);
    setActiveWidgets(prev => {
      const current = prev[sha] || [];
      if (current.includes(widgetName)) {
        return { ...prev, [sha]: current.filter(w => w !== widgetName) };
      }
      return { ...prev, [sha]: [...current, widgetName] };
    });

    if (!branchData[sha] && (widgetName === 'files' || widgetName === 'details')) {
      try {
        const token = sessionStorage.getItem('GITHUB_TOKEN');
        const res = await fetch(`${API}/github/repos/${repo.owner}/${repo.name}/commits/${sha}`, {
          headers: { 'X-GitHub-Token': token }
        });
        if (res.ok) {
          const data = await res.json();
          setBranchData(prev => ({ ...prev, [sha]: data }));
        }
      } catch (err) {
        console.error("Failed to fetch branch details", err);
      }
    }
  };

  // Formata texto com Markdown básico para as bolhas do chat
  const formatChatText = (text) => {
    if (!text) return '';
    return text
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')           // **negrito**
      .replace(/`([^`]+)`/g, '<code class="bg-black/30 px-1 rounded text-xs font-mono">$1</code>') // `code`
      .replace(/\n/g, '<br />')                                    // quebras de linha
      .replace(/^\s*[-•]\s(.+)/gm, '<span class="block pl-2 before:content-[\'•\'] before:mr-1">$1</span>'); // listas
  };

  // ─── Limpar histórico do chat (UI + memória persistida no backend) ───
  const clearChat = async () => {
    setChatMessages([]);
    const sessionId = repo ? `${repo.owner}_${repo.name}`.replace(/[^a-zA-Z0-9-_.]/g, '_') : null;
    if (!sessionId) return;
    try {
      await fetch(`${API}/ai/sessions/${sessionId}`, { method: 'DELETE' });
    } catch (e) {
      console.warn('[Copilot] Falha ao limpar sessão no backend:', e);
    }
  };

  // ─── SAST: Análise de Commit Individual ───
  const expandSASTAnalysis = async (commit) => {
    const sha = commit.sha;
    setOpenMenuSha(null);

    // Ativa widget 'sast' no mapa mental para criar o card filho
    setActiveWidgets(prev => {
      const current = prev[sha] || [];
      if (current.includes('sast')) return prev;
      return { ...prev, [sha]: [...current, 'sast'] };
    });

    // Marca como carregando
    setSastResults(prev => ({ ...prev, [sha]: { loading: true } }));

    const geminiKey = sessionStorage.getItem('gemini_api_key');
    const token = sessionStorage.getItem('GITHUB_TOKEN');

    try {
      // Busca os arquivos/patch do commit se ainda não temos
      let files = branchData[sha]?.files || [];
      if (!files.length && token) {
        const r = await fetch(`${API}/github/repos/${repo.owner}/${repo.name}/commits/${sha}`, {
          headers: { 'X-GitHub-Token': token }
        });
        if (r.ok) {
          const d = await r.json();
          setBranchData(prev => ({ ...prev, [sha]: d }));
          files = d.files || [];
        }
      }

      const headers = { 'Content-Type': 'application/json' };
      if (geminiKey) headers['X-Gemini-Key'] = geminiKey;

      const res = await fetch(`${API}/sast/analyze-commit`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          sha:     sha,
          message: commit.message,
          author:  commit.author,
          date:    commit.date,
          branch:  commit.branch_name,
          files:   files.map(f => ({ filename: f.filename, patch: f.patch || '' })),
          repo_url: `https://github.com/${repo.owner}/${repo.name}.git`
        })
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      
      // Injeta os dados recebidos diretamente no objeto em memória
      commit.scanner_results = data.scanner_results;
      setCommits(prev => prev.map(c => c.sha === sha ? { ...c, scanner_results: data.scanner_results } : c));

      // Salva resultados técnicos e garante que `analysis` está nulo inicialmente
      setSastResults(prev => ({ ...prev, [sha]: { ...data, loading: false, analysis: null } }));
      
      // Gravação na Memória do Navegador para persistência em F5 / troca de abas
      localStorage.setItem('previswit_scan_' + sha, JSON.stringify({
        vulnerable:      data.vulnerable,
        severity:        data.severity,
        scan_status:     data.scan_status,
        scanner_results: data.scanner_results,
      }));
    } catch (e) {
      setSastResults(prev => ({ ...prev, [sha]: {
        loading: false,
        vulnerable: null,
        severity: 'ERROR',
        scanner_results: [],
        analysis: `⚠️ Falha ao executar análise técnica: ${e.message}`,
        tools_used: []
      }}));
    }
  };

  const showFullScannerResults = (scannerData) => {
    setFullSastData(scannerData);
  };

  const generateCommitSummary = async (commit) => {
    const sha = commit.sha;
    setOpenMenuSha(null);
    
    setActiveWidgets(prev => {
      const current = prev[sha] || [];
      if (!current.includes('ia')) return { ...prev, [sha]: [...current, 'ia'] };
      return prev;
    });

    if (aiSummaries[sha]?.text) return; // already generated
    
    setAiSummaries(prev => ({ ...prev, [sha]: { loading: true, text: null } }));
    
    const apiKey = sessionStorage.getItem('gemini_api_key');
    if (!apiKey) {
      alert("⚠️ Configuração Pendente: Insira sua GEMINI_API_KEY na aba de Integrações.");
      setAiSummaries(prev => ({ ...prev, [sha]: { loading: false, text: "Chave de API não configurada." } }));
      return;
    }

    const token = sessionStorage.getItem('GITHUB_TOKEN');
    try {
      let files = branchData[sha]?.files || [];
      if (!files.length && token) {
        const r = await fetch(`${API}/github/repos/${repo.owner}/${repo.name}/commits/${sha}`, {
          headers: { 'X-GitHub-Token': token }
        });
        if (r.ok) {
          const d = await r.json();
          setBranchData(prev => ({ ...prev, [sha]: d }));
          files = d.files || [];
        }
      }

      const res = await fetch(`${API}/ai/summarize-commit`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Gemini-Key': apiKey
        },
        body: JSON.stringify({
          sha,
          message: commit.message,
          author: commit.author,
          date: commit.date,
          files: files.map(f => ({ filename: f.filename, patch: f.patch || '' }))
        })
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      
      setAiSummaries(prev => ({ ...prev, [sha]: { loading: false, text: data.summary } }));
    } catch (err) {
      setAiSummaries(prev => ({ ...prev, [sha]: { loading: false, text: `⚠️ Falha ao gerar resumo: ${err.message}` } }));
    }
  };

  const requestAIValidation = async (commit) => {
    const sha = commit.sha;
    setSastResults(prev => ({
      ...prev,
      [sha]: { ...prev[sha], aiLoading: true }
    }));

    const geminiKey = sessionStorage.getItem('gemini_api_key');
    const token = sessionStorage.getItem('GITHUB_TOKEN');

    try {
      let files = branchData[sha]?.files || [];
      if (!files.length && token) {
        const r = await fetch(`${API}/github/repos/${repo.owner}/${repo.name}/commits/${sha}`, {
          headers: { 'X-GitHub-Token': token }
        });
        if (r.ok) {
          const d = await r.json();
          setBranchData(prev => ({ ...prev, [sha]: d }));
          files = d.files || [];
        }
      }

      const apiKey = sessionStorage.getItem('gemini_api_key');
      const headers = { 
        'Content-Type': 'application/json',
        'X-Gemini-Key': apiKey || ''
      };

      const currentSast = sastResults[sha] || {};

      const res = await fetch(`${API}/ai/validate-sast`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          sha:     sha,
          message: commit.message,
          author:  commit.author,
          date:    commit.date,
          branch:  commit.branch_name,
          files:   files.map(f => ({ filename: f.filename, patch: f.patch || '' })),
          scanner_results: currentSast.scanner_results || []
        })
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      
      setSastResults(prev => ({
        ...prev,
        [sha]: { ...prev[sha], aiLoading: false, analysis: data.analysis }
      }));
    } catch (e) {
      setSastResults(prev => ({
        ...prev,
        [sha]: { ...prev[sha], aiLoading: false, analysis: `⚠️ Falha na validação IA: ${e.message}` }
      }));
    }
  };

  // ─── SAST Executivo (Business View) ───
  const quickExecutiveSAST = async (type, hash) => {
    setIsCopilotMenuOpen(false);
    setIsChatPanelOpen(true);
    setExecutiveSASTStep(0);
    setExecutiveSASTHash('');

    const loadingId = Date.now();
    setChatMessages(prev => [...prev, {
      id: loadingId,
      role: 'assistant',
      content: "Clonando repositório e executando Scanners Nativos...",
      isLoading: true
    }]);

    const geminiKey = sessionStorage.getItem('gemini_api_key');
    const token = sessionStorage.getItem('GITHUB_TOKEN');

    try {
      let targetCommits = [];
      if (type === 'specific') {
        const c = commits.find(x => x.sha.startsWith(hash.trim()));
        if (!c) throw new Error("Commit não encontrado no grafo (verifique o Hash).");
        targetCommits = [c];
      } else {
        // Analisa os top 5 recentes
        targetCommits = commits.slice(0, 5);
      }

      // Cada commit é escaneado individualmente e empacotado com sua identidade
      const commitsData = [];

      for (const commit of targetCommits) {
        const sha = commit.sha;
        let files = branchData[sha]?.files || [];
        if (!files.length && token) {
          const r = await fetch(`${API}/github/repos/${repo.owner}/${repo.name}/commits/${sha}`, {
            headers: { 'X-GitHub-Token': token }
          });
          if (r.ok) {
            const d = await r.json();
            files = d.files || [];
            setBranchData(prev => ({ ...prev, [sha]: d }));
          }
        }

        const sastRes = await fetch(`${API}/sast/analyze-commit`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            sha,
            message: commit.message,
            author:  commit.author,
            date:    commit.date,
            branch:  commit.branch_name,
            files:   files.map(f => ({ filename: f.filename, patch: f.patch || '' })),
            repo_url: `https://github.com/${repo.owner}/${repo.name}.git`
          })
        });

        if (sastRes.ok) {
          const sastData = await sastRes.json();
          // Atualiza o badge do commit na árvore
          setSastResults(prev => ({ ...prev, [sha]: { ...sastData, loading: false, analysis: null } }));
          commitsData.push({
            sha:             commit.sha,
            message:         commit.message,
            author:          commit.author,
            date:            commit.date,
            branch:          commit.branch_name,
            files:           files.map(f => ({ filename: f.filename, patch: f.patch || '' })),
            vulnerable:      sastData.vulnerable,
            severity:        sastData.severity,
            scanner_results: sastData.scanner_results,
          });
        }
      }

      const apiKey = sessionStorage.getItem('gemini_api_key');
      const headers = {
        'Content-Type': 'application/json',
        'X-Gemini-Key': apiKey || ''
      };

      const mainCommit = targetCommits[0];

      const aiRes = await fetch(`${API}/ai/validate-sast`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          sha:          mainCommit.sha,
          message:      'Análise executiva de múltiplos commits',
          author:       mainCommit.author,
          date:         mainCommit.date,
          branch:       mainCommit.branch_name,
          commits_data: commitsData,
          executive_mode: true
        })
      });

      if (!aiRes.ok) throw new Error("Erro na IA Executiva");
      const aiData = await aiRes.json();

      setChatMessages(prev => prev.map(m => m.id === loadingId ? {
        role: 'assistant',
        content: `**Resumo Executivo de Riscos**\n\n${aiData.analysis}`,
        relatedSha: mainCommit.sha
      } : m));

      // Scroll para o fim
      setTimeout(() => {
        const chatContainer = document.getElementById('chat-messages-container');
        if (chatContainer) chatContainer.scrollTop = chatContainer.scrollHeight;
      }, 100);

    } catch (e) {
      setChatMessages(prev => prev.map(m => m.id === loadingId ? {
        role: 'assistant',
        content: `⚠️ Falha na Análise SAST Executiva: ${e.message}`
      } : m));
    }
  };

  const markAsFixed = (sha) => {
    setFixedCommits(prev => ({ ...prev, [sha]: true }));
  };


  // ─── Extrator de Contexto: Gera JSON estruturado dos commits visíveis na tela ───
  // Esquema: [{ hash, autor, data, mensagem, branch, tipo }]
  // Reutilizável por outros agentes da plataforma que precisem do mesmo snapshot.
  const extractCommitsToJSON = () => {
    const commitCards = document.querySelectorAll('[data-commit="true"]');
    const commitArray = [];
    commitCards.forEach(card => {
      commitArray.push({
        hash:     card.getAttribute('data-sha')      || card.getAttribute('data-hash') || "",
        autor:    card.getAttribute('data-author')   || "",
        data:     card.getAttribute('data-date')     || "",
        mensagem: card.getAttribute('data-message')  || "",
        branch:   card.getAttribute('data-branch')   || "",
        tipo:     card.getAttribute('data-type')     || (card.getAttribute('data-is-main') === 'true' ? 'main' : 'pr'),
      });
    });
    return commitArray;
  };

  const sendAIQuery = async (promptText) => {
    // Validação BYOK (Bring Your Own Key) via Sessão
    const geminiKey = sessionStorage.getItem('gemini_api_key');
    console.log("[DEBUG IA] Chave resgatada da sessão:", geminiKey ? "SIM" : "NÃO");

    if (!geminiKey) {
      alert("⚠️ Configuração Pendente: Insira sua GEMINI_API_KEY na aba de Integrações.");
      return;
    }

    setIsCopilotMenuOpen(false);
    setIsChatPanelOpen(true);

    const userMsg = { role: 'user', content: promptText };
    setChatMessages(prev => [...prev, userMsg]);
    setIsAiThinking(true);
    setChatInput('');

    // Auto-scroll para a mensagem do usuário
    setTimeout(() => chatEndRef.current?.scrollIntoView({ behavior: 'smooth' }), 50);

    // session_id é o identificador único da sessão de memória deste repositório
    const sessionId = `${repo.owner}_${repo.name}`.replace(/[^a-zA-Z0-9-_.]/g, '_');

    // Extração de Contexto: monta JSON estruturado dos commits visíveis no Mapa Mental
    const commitsJSON = extractCommitsToJSON();
    const screenContext = JSON.stringify(commitsJSON, null, 2);
    console.log(`[DEBUG IA] Commits extraídos para contexto: ${commitsJSON.length} cards encontrados.`);

    try {
      const res = await fetch(`${API}/ai/chat`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'X-Gemini-Key': geminiKey 
        },
        body: JSON.stringify({
          session_id: sessionId,
          message: promptText,
          context: screenContext
        })
      });

      if (res.ok) {
        const data = await res.json();
        setChatMessages(prev => [...prev, { role: 'assistant', content: data.response }]);
      } else {
        const errData = await res.json().catch(() => ({}));
        setChatMessages(prev => [...prev, {
          role: 'assistant',
          content: `⚠️ ${errData.detail || 'Erro ao processar a requisição no servidor.'}`
        }]);
      }
    } catch (e) {
      setChatMessages(prev => [...prev, {
        role: 'assistant',
        content: '⚠️ Erro de comunicação com o servidor de IA. Verifique se o backend está rodando.'
      }]);
    } finally {
      setIsAiThinking(false);
      // Auto-scroll para a resposta da IA forçando scrollTop no container
      setTimeout(() => {
        chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
        const container = document.getElementById('chat-messages-container');
        if (container) container.scrollTop = container.scrollHeight;
      }, 100);
    }
  };

  const openIDEModal = async (sha) => {
    setSelectedIDECommit(sha);
    setSelectedIDEFile(null);
    if (!branchData[sha]) {
      setIdeLoading(true);
      try {
        const token = sessionStorage.getItem('GITHUB_TOKEN');
        const res = await fetch(`${API}/github/repos/${repo.owner}/${repo.name}/commits/${sha}`, {
          headers: { 'X-GitHub-Token': token }
        });
        if (res.ok) {
          const data = await res.json();
          setBranchData(prev => ({ ...prev, [sha]: data }));
          if (data.files && data.files.length > 0) {
            setSelectedIDEFile(data.files[0]);
          }
        }
      } catch (err) {
        console.error("Failed to fetch commit details", err);
      } finally {
        setIdeLoading(false);
      }
    } else {
      const data = branchData[sha];
      if (data.files && data.files.length > 0) {
        setSelectedIDEFile(data.files[0]);
      }
    }
  };

  // Filter and Sort Logic
  const visibleCommits = useMemo(() => {
    let result = [...commits];

    if (activeFilters.author) {
      result = result.filter(c => c.author === activeFilters.author);
    }

    if (activeFilters.date) {
      const filterDate = new Date(activeFilters.date).getTime();
      result = result.filter(c => new Date(c.date).getTime() >= filterDate);
    }

    if (activeFilters.sort === 'asc') {
      result.sort((a, b) => new Date(a.date) - new Date(b.date));
    } else {
      result.sort((a, b) => new Date(b.date) - new Date(a.date));
    }

    return result;
  }, [commits, activeFilters]);

  const uniqueAuthors = useMemo(() => {
    const authors = new Set(commits.map(c => c.author));
    return Array.from(authors);
  }, [commits]);

  // Node Dragging Handlers
  const handleNodeDragStart = (e, id) => {
    e.preventDefault();
    e.stopPropagation();
    maxZIndex.current += 1;
    setNodePositions(prev => ({
      ...prev,
      [id]: { ...prev[id], zIndex: maxZIndex.current }
    }));
    dragNodeRef.current = {
      id,
      startX: e.clientX,
      startY: e.clientY,
      initialX: nodePositions[id].x,
      initialY: nodePositions[id].y
    };
    window.addEventListener('mousemove', handleNodeDragMove, { passive: false });
    window.addEventListener('mouseup', handleNodeDragEnd);
  };

  const handleNodeDragMove = useCallback((e) => {
    if (!dragNodeRef.current) return;
    const { id, startX, startY, initialX, initialY } = dragNodeRef.current;

    // Matemática do Zoom: O movimento real é dividido pela escala atual
    const deltaX = (e.clientX - startX) / transform.scale;
    const deltaY = (e.clientY - startY) / transform.scale;

    setNodePositions(prev => ({
      ...prev,
      [id]: { ...prev[id], x: initialX + deltaX, y: initialY + deltaY }
    }));
  }, [transform.scale]);

  const handleNodeDragEnd = useCallback(() => {
    dragNodeRef.current = null;
    window.removeEventListener('mousemove', handleNodeDragMove);
    window.removeEventListener('mouseup', handleNodeDragEnd);
  }, [handleNodeDragMove]);

  // Canvas Pan & Zoom
  const handleWheel = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    const scaleAdjust = e.deltaY > 0 ? 0.9 : 1.1;
    setTransform(prev => {
      let newScale = prev.scale * scaleAdjust;
      if (newScale < 0.2) newScale = 0.2;
      if (newScale > 3) newScale = 3;
      return { ...prev, scale: newScale };
    });
  }, []);

  const handleCanvasMouseDown = (e) => {
    if (e.target.closest('.no-pan') || e.target.closest('.cursor-move')) return;
    setIsDraggingCanvas(true);
    dragCanvasStart.current = { x: e.clientX - transform.x, y: e.clientY - transform.y };
  };

  const handleCanvasMouseMove = (e) => {
    if (!isDraggingCanvas) return;
    setTransform(prev => ({
      ...prev,
      x: e.clientX - dragCanvasStart.current.x,
      y: e.clientY - dragCanvasStart.current.y
    }));
  };

  const handleCanvasMouseUp = () => setIsDraggingCanvas(false);

  useEffect(() => {
    const el = containerRef.current;
    if (el) {
      el.addEventListener('wheel', handleWheel, { passive: false });
      return () => el.removeEventListener('wheel', handleWheel);
    }
  }, [handleWheel]);

  // Helper for drawing lines
  const renderLine = (x1, y1, x2, y2, color, strokeDasharray = "none") => {
    if (x1 == null || y1 == null || x2 == null || y2 == null) return null;
    // Calculate a bounding box for the SVG so it doesn't just span the whole 5000x5000 with massive invisible area
    // Actually, drawing an absolute 5000x5000 SVG once is easier.
    return (
      <path
        d={`M ${x1} ${y1} L ${x2} ${y2}`}
        fill="transparent"
        stroke={color}
        strokeWidth="3"
        strokeDasharray={strokeDasharray}
      />
    );
  };

  const renderCurve = (x1, y1, x2, y2, color, strokeDasharray = "none") => {
    if (x1 == null || y1 == null || x2 == null || y2 == null) return null;
    return (
      <path
        d={`M ${x1} ${y1} C ${(x1 + x2) / 2} ${y1}, ${(x1 + x2) / 2} ${y2}, ${x2} ${y2}`}
        fill="transparent"
        stroke={color}
        strokeWidth="2"
        strokeDasharray={strokeDasharray}
      />
    );
  };

  return (
    <section id="view-risk-graph" className="view-section w-full h-full flex flex-col gap-4">
      {/* Cabeçalho */}
      <div className="flex items-center gap-4">
        <button
          onClick={onBack}
          className="p-2 rounded-lg border border-white/10 text-gray-400 hover:text-white hover:bg-white/5 transition-all"
        >
          <ArrowLeft className="w-5 h-5" />
        </button>
        <div>
          <h1 className="text-xl font-semibold text-white">Mapa Mental Dinâmico: {repo?.name}</h1>
          <p className="text-sm text-gray-500">Arraste e Redimensione os nós da Árvore da Vida</p>
        </div>
      </div>

      {/* Viewport */}
      <div
        id="canvas-viewport"
        ref={containerRef}
        className={`flex-1 min-h-[70vh] overflow-hidden overscroll-none touch-none select-none relative w-full bg-[#060b13] border border-white/5 rounded-xl ${isDraggingCanvas ? 'cursor-grabbing' : 'cursor-grab'}`}
        onMouseDown={handleCanvasMouseDown}
        onMouseMove={handleCanvasMouseMove}
        onMouseUp={handleCanvasMouseUp}
        onMouseLeave={handleCanvasMouseUp}
        onClick={() => setOpenMenuSha(null)}
      >
        {/* Container Pai dos Flutuantes Top-Left */}
        <div 
          className="absolute top-4 left-4 z-50 flex flex-col gap-3 no-pan cursor-default"
          onMouseDown={(e) => e.stopPropagation()}
          onWheel={(e) => e.stopPropagation()}
        >
          {/* GRUPO FILTROS */}
          <div className="relative flex flex-col gap-2">
            <button 
              onClick={() => { setIsFilterOpen(!isFilterOpen); setIsCopilotMenuOpen(false); }}
              className="w-10 h-10 rounded-full bg-[#0d1421] border border-slate-700 shadow-xl flex items-center justify-center text-gray-400 hover:text-white hover:bg-slate-800 transition-colors"
              title="Filtros"
            >
              <Filter className="w-5 h-5" />
            </button>

            {isFilterOpen && (
              <div className="absolute top-0 left-14 bg-slate-900/90 backdrop-blur-md border border-slate-700 p-4 rounded-xl shadow-2xl flex flex-col gap-4 animate-in fade-in slide-in-from-left-2 w-64">
                <div className="flex flex-col gap-1">
                  <label className="text-[10px] text-gray-400 font-semibold uppercase tracking-wider flex items-center gap-1"><User className="w-3 h-3" /> Autor</label>
                  <select
                    className="bg-[#0b111a] border border-white/10 rounded-lg px-3 py-1.5 text-sm text-gray-200 outline-none focus:border-purple-500"
                    value={draftFilters.author}
                    onChange={(e) => setDraftFilters(f => ({ ...f, author: e.target.value }))}
                  >
                    <option value="">Todos os Autores</option>
                    {uniqueAuthors.map(a => <option key={a} value={a}>{a}</option>)}
                  </select>
                </div>

                <div className="flex flex-col gap-1">
                  <label className="text-[10px] text-gray-400 font-semibold uppercase tracking-wider flex items-center gap-1"><Clock className="w-3 h-3" /> A partir de</label>
                  <input
                    type="date"
                    className="bg-[#0b111a] border border-white/10 rounded-lg px-3 py-1.5 text-sm text-gray-200 outline-none focus:border-purple-500 [color-scheme:dark]"
                    value={draftFilters.date}
                    onChange={(e) => setDraftFilters(f => ({ ...f, date: e.target.value }))}
                  />
                </div>

                <div className="flex flex-col gap-1">
                  <label className="text-[10px] text-gray-400 font-semibold uppercase tracking-wider flex items-center gap-1"><Filter className="w-3 h-3" /> Ordenação</label>
                  <select
                    className="bg-[#0b111a] border border-white/10 rounded-lg px-3 py-1.5 text-sm text-gray-200 outline-none focus:border-purple-500"
                    value={draftFilters.sort}
                    onChange={(e) => setDraftFilters(f => ({ ...f, sort: e.target.value }))}
                  >
                    <option value="desc">Mais Recente</option>
                    <option value="asc">Mais Antigo</option>
                  </select>
                </div>

                <button
                  className="w-full bg-purple-600 hover:bg-purple-500 text-white text-sm font-semibold py-2 rounded-lg transition-colors shadow-lg mt-1"
                  onClick={() => {
                    setActiveFilters(draftFilters);
                    setIsFilterOpen(false);
                  }}
                >
                  Salvar Filtros
                </button>
              </div>
            )}
          </div>

          {/* GRUPO COPILOT */}
          <div className="relative flex flex-col gap-2">
            <button 
              onClick={() => { setIsCopilotMenuOpen(!isCopilotMenuOpen); setIsFilterOpen(false); }}
              className="w-10 h-10 rounded-full bg-indigo-600/20 border border-indigo-500 shadow-xl shadow-indigo-500/20 flex items-center justify-center text-indigo-400 hover:text-white hover:bg-indigo-600/40 transition-all"
              title="IA Copilot"
            >
              <Shield className="w-5 h-5" />
            </button>

            {isCopilotMenuOpen && (
              <div className="absolute top-0 left-14 bg-slate-900/90 backdrop-blur-md border border-slate-700 p-2 rounded-xl shadow-2xl flex flex-col gap-1 w-64 animate-in fade-in slide-in-from-left-2">
                <div className="text-[10px] text-gray-400 font-semibold uppercase tracking-wider mb-2 px-2 pt-1">Ações Rápidas</div>
                
                {executiveSASTStep === 0 && (
                  <>
                    <button onClick={() => sendAIQuery("Resuma os riscos deste projeto.")} className="text-left px-3 py-2 rounded-lg text-sm text-gray-300 hover:bg-indigo-600/20 hover:text-indigo-300 flex items-center gap-2 transition-colors">
                      <FileText className="w-4 h-4" /> Resumir Riscos
                    </button>
                    <button onClick={() => setExecutiveSASTStep(1)} className="text-left px-3 py-2 rounded-lg text-sm text-gray-300 hover:bg-indigo-600/20 hover:text-indigo-300 flex items-center gap-2 transition-colors">
                      <Activity className="w-4 h-4" /> Análise SAST (Executiva)
                    </button>
                    <div className="h-px bg-white/5 my-1" />
                    <button onClick={() => { setIsCopilotMenuOpen(false); setIsChatPanelOpen(true); }} className="text-left px-3 py-2 rounded-lg text-sm text-gray-300 hover:bg-slate-800 flex items-center gap-2 transition-colors">
                      <MessageSquare className="w-4 h-4" /> Chat Livre
                    </button>
                  </>
                )}

                {executiveSASTStep === 1 && (
                  <div className="flex flex-col gap-2 p-1">
                    <p className="text-xs text-gray-300 px-1 mb-1">Analisar quais commits?</p>
                    <button onClick={() => quickExecutiveSAST('all', null)} className="bg-indigo-600/20 hover:bg-indigo-600/40 border border-indigo-500/30 text-indigo-300 text-xs py-1.5 rounded-lg transition-colors">
                      Todos os Commits
                    </button>
                    <button onClick={() => setExecutiveSASTStep(2)} className="bg-slate-800 hover:bg-slate-700 border border-white/10 text-gray-300 text-xs py-1.5 rounded-lg transition-colors">
                      Commit Específico
                    </button>
                    <button onClick={() => setExecutiveSASTStep(0)} className="text-[10px] text-gray-500 hover:text-gray-400 mt-1">
                      Cancelar
                    </button>
                  </div>
                )}

                {executiveSASTStep === 2 && (
                  <div className="flex flex-col gap-2 p-1">
                    <p className="text-xs text-gray-300 px-1 mb-1">Cole o Hash do Commit:</p>
                    <input 
                      type="text" 
                      placeholder="Ex: a1b2c3d..." 
                      className="bg-[#0b111a] border border-white/10 rounded-lg px-3 py-1.5 text-xs text-gray-200 outline-none focus:border-indigo-500"
                      value={executiveSASTHash}
                      onChange={(e) => setExecutiveSASTHash(e.target.value)}
                    />
                    <button 
                      onClick={() => quickExecutiveSAST('specific', executiveSASTHash)}
                      disabled={!executiveSASTHash}
                      className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs py-1.5 rounded-lg transition-colors mt-1"
                    >
                      Iniciar Análise
                    </button>
                    <button onClick={() => setExecutiveSASTStep(0)} className="text-[10px] text-gray-500 hover:text-gray-400 mt-1">
                      Cancelar
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Painel de Chat Fixo Lateral */}
        {isChatPanelOpen && (
          <div 
            id="ai-chat-panel"
            className="absolute top-32 left-4 z-40 w-96 h-[65vh] flex flex-col bg-slate-900/95 backdrop-blur-md border border-slate-700 rounded-xl shadow-2xl animate-in fade-in slide-in-from-left-4 no-pan"
            onMouseDown={(e) => e.stopPropagation()}
            onWheel={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div className="h-14 border-b border-white/10 flex items-center justify-between px-4 shrink-0 bg-indigo-900/20 rounded-t-xl">
              <div className="flex items-center gap-2">
                <Bot className="w-5 h-5 text-indigo-400" />
                <span className="font-semibold text-sm text-indigo-100">Gemini Security Copilot</span>
              </div>
              <div className="flex items-center gap-1">
                <button
                  onClick={clearChat}
                  title="Limpar conversa"
                  className="p-1.5 text-gray-400 hover:text-red-400 hover:bg-red-500/10 rounded-md transition-colors"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
                <button onClick={() => setIsChatPanelOpen(false)} className="p-1.5 text-gray-400 hover:text-white hover:bg-white/5 rounded-md transition-colors">
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Messages */}
            <div id="chat-messages-container" className="flex-1 overflow-y-auto custom-scrollbar p-4 space-y-4">
              {chatMessages.map((msg, i) => (
                <div key={i} className={`flex flex-col ${msg.role === 'user' ? 'items-end' : 'items-start'}`}>
                  <div className={`max-w-[90%] p-3 text-[13px] leading-relaxed shadow-md ${msg.role === 'user' ? 'bg-indigo-600 text-white rounded-2xl rounded-tr-sm' : 'bg-slate-800 text-gray-200 border border-slate-700 rounded-2xl rounded-tl-sm'}`}>
                    <pre className="whitespace-pre-wrap font-sans break-words">{msg.content}</pre>
                    {msg.relatedSha && (
                      <button
                        onClick={() => {
                          setIsChatPanelOpen(false);
                          setIsCopilotMenuOpen(false);
                          const el = document.getElementById(`commit-${msg.relatedSha}`);
                          if (el) {
                             el.scrollIntoView({ behavior: 'smooth', block: 'center', inline: 'center' });
                             const oldShadow = el.style.boxShadow;
                             el.style.boxShadow = '0 0 30px rgba(99, 102, 241, 0.8)';
                             el.style.borderColor = '#818cf8';
                             setTimeout(() => {
                               el.style.boxShadow = oldShadow;
                               el.style.borderColor = '';
                             }, 2500);
                          }
                        }}
                        className="mt-3 bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-md font-semibold text-xs flex items-center justify-center gap-2 w-full transition-colors border border-indigo-500 shadow-md"
                      >
                        📍 Ver no Mapa Mental de Commits
                      </button>
                    )}
                  </div>
                </div>
              ))}
              {isAiThinking && (
                <div className="flex items-start">
                  <div className="p-4 rounded-2xl rounded-tl-sm bg-slate-800 text-gray-400 border border-slate-700 flex items-center gap-1.5 shadow-md">
                    <div className="w-1.5 h-1.5 bg-indigo-400 rounded-full animate-bounce" />
                    <div className="w-1.5 h-1.5 bg-indigo-400 rounded-full animate-bounce [animation-delay:0.2s]" />
                    <div className="w-1.5 h-1.5 bg-indigo-400 rounded-full animate-bounce [animation-delay:0.4s]" />
                  </div>
                </div>
              )}
            </div>

            {/* Input */}
            <div className="p-3 border-t border-white/10 bg-[#0d1421] rounded-b-xl shrink-0">
              <form 
                onSubmit={(e) => { e.preventDefault(); if (chatInput.trim()) sendAIQuery(chatInput); }}
                className="relative flex items-center"
              >
                <input 
                  type="text" 
                  className="w-full bg-[#060b13] border border-slate-700 rounded-lg pl-3 pr-10 py-2.5 text-sm text-white placeholder-gray-500 outline-none focus:border-indigo-500 transition-colors"
                  placeholder="Mensagem para o Gemini..."
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                />
                <button type="submit" disabled={!chatInput.trim() || isAiThinking} className="absolute right-2 p-1.5 text-indigo-400 hover:text-indigo-300 hover:bg-white/5 rounded-md disabled:opacity-50 transition-colors">
                  <Send className="w-4 h-4" />
                </button>
              </form>
            </div>
          </div>
        )}

        <div
          id="risk-graph-canvas"
          className="absolute"
          style={{
            width: 5000,
            height: 5000,
            transform: `translate(${transform.x}px, ${transform.y}px) scale(${transform.scale})`,
            transformOrigin: '0 0',
            backgroundImage: 'radial-gradient(circle, rgba(255,255,255,0.05) 2px, transparent 2px)',
            backgroundSize: '40px 40px'
          }}
        >
          {loading && (
            <div className="absolute top-[2500px] left-[2500px] text-purple-400 flex items-center gap-2 -translate-x-1/2 -translate-y-1/2">
              <div className="w-5 h-5 border-2 border-purple-500 border-t-transparent rounded-full animate-spin" />
              Carregando Mapa...
            </div>
          )}

          {/* SVG Global Layer (Conexões) */}
          <svg className="absolute inset-0 w-full h-full pointer-events-none z-0">
            {visibleCommits.map(commit => {
              const pos = nodePositions[commit.sha];
              if (!pos) return null;

              const lines = [];

              // Main Timeline Line
              if (pos.isMain && pos.nextMainSha && nodePositions[pos.nextMainSha]) {
                const nextPos = nodePositions[pos.nextMainSha];
                lines.push(<React.Fragment key={`main-${commit.sha}`}>{renderLine(pos.x, pos.y, nextPos.x, nextPos.y, "rgba(168, 85, 247, 0.4)")}</React.Fragment>);
              }

              // PR Line back to base
              if (!pos.isMain && commit.base_sha && nodePositions[commit.base_sha]) {
                const basePos = nodePositions[commit.base_sha];
                lines.push(<React.Fragment key={`pr-${commit.sha}`}>{renderCurve(pos.x, pos.y, basePos.x, basePos.y, "rgba(245, 158, 11, 0.4)", "6 6")}</React.Fragment>);
              }

              // Widget Lines
              const widgets = activeWidgets[commit.sha] || [];
              widgets.forEach(w => {
                const wPos = nodePositions[`${commit.sha}-${w}`];
                if (wPos) {
                  lines.push(<React.Fragment key={`w-${commit.sha}-${w}`}>{renderCurve(pos.x, pos.y, wPos.x, wPos.y, "rgba(255, 255, 255, 0.2)", "6 6")}</React.Fragment>);
                }
              });

              return lines;
            })}
          </svg>

          {/* Cards Layer */}
          {!loading && !error && visibleCommits.map(commit => {
            const pos = nodePositions[commit.sha];
            if (!pos) return null;

            const isMain = pos.isMain;
            const widgets = activeWidgets[commit.sha] || [];

            return (
              <React.Fragment key={commit.sha}>
                {/* Commit Card */}
                <div
                  id={`commit-${commit.sha}`}
                  data-commit="true"
                  data-sha={commit.sha}
                  data-author={commit.author}
                  data-date={commit.date}
                  data-message={commit.message}
                  data-branch={commit.branch_name}
                  data-is-main={String(isMain)}
                  className={`no-pan absolute flex flex-col resize overflow-hidden w-72 min-h-[200px] h-auto max-h-[500px] bg-slate-900/90 rounded-lg shadow-xl text-sm
                             ${isMain ? 'border border-slate-700 hover:shadow-purple-500/10' : 'border border-amber-500/40 hover:shadow-amber-500/10'}`}
                  style={{ left: pos.x, top: pos.y, transform: 'translate(-50%, -50%)', zIndex: pos.zIndex }}
                  onMouseDown={(e) => {
                    maxZIndex.current += 1;
                    setNodePositions(p => ({ ...p, [commit.sha]: { ...p[commit.sha], zIndex: maxZIndex.current } }));
                  }}
                  onWheel={(e) => e.stopPropagation()}
                >
                  {/* Cabeçalho de Arrasto */}
                  <div
                    className="cursor-move bg-black/40 p-1.5 flex items-center justify-center border-b border-white/5 hover:bg-black/60 transition-colors shrink-0"
                    onMouseDown={(e) => handleNodeDragStart(e, commit.sha)}
                  >
                    <GripHorizontal className="w-4 h-4 text-gray-500" />
                  </div>

                  {/* Corpo do Card */}
                  <div className="flex-1 overflow-y-auto p-3 break-words relative group custom-scrollbar">
                    <div className="flex items-start gap-3">
                      <div className={`shrink-0 p-2 rounded-lg border ${isMain ? 'bg-purple-500/10 border-purple-500/20' : 'bg-amber-500/10 border-amber-500/20'}`}>
                        {isMain ? <GitCommit className="w-4 h-4 text-purple-400" /> : <GitPullRequest className="w-4 h-4 text-amber-400" />}
                      </div>
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-semibold text-white truncate" title={commit.message}>
                          {commit.message}
                        </p>
                        <p className={`text-[10px] mt-1 font-mono ${isMain ? 'text-purple-400' : 'text-amber-400'}`}>
                          {commit.branch_name} • {commit.sha.substring(0, 7)}
                        </p>
                        
                        {/* Status Badges */}
                        {(() => {
                          const scanInfo = sastResults[commit.sha];
                          const hasScannerResults = commit.scanner_results && Object.keys(commit.scanner_results).length > 0;
                          
                          const isPendingScan = !scanInfo && !hasScannerResults;
                          const isScanning = scanInfo && scanInfo.loading;
                          const isScanComplete = (scanInfo && !scanInfo.loading) || hasScannerResults;
                          // Se a API retornou um resultado fresco, confiar nele diretamente.
                          // A heurística de commit.scanner_results só serve de fallback para
                          // cache legado (sem campo vulnerable explícito da API).
                          let isVuln = scanInfo?.vulnerable === true;

                          if (!scanInfo && commit.scanner_results) {
                            if (commit.scanner_results.clean === true) {
                              isVuln = false;
                            } else if (Array.isArray(commit.scanner_results.vulnerabilities)) {
                              isVuln = commit.scanner_results.vulnerabilities.length > 0;
                            } else if (commit.scanner_results.inherited) {
                              isVuln = commit.scanner_results.clean === false;
                            }
                          }
                          return (
                            <div className="flex flex-wrap gap-1 mt-2">
                              {isPendingScan && (
                                <span className="badge-pendente bg-amber-500/10 text-amber-400 border border-amber-500/30 rounded-full px-1.5 py-0.5 text-[9px] font-bold tracking-wide">
                                  ⏳ Pendente de Scan
                                </span>
                              )}
                              {isScanning && (
                                <span className="bg-blue-500/10 text-blue-400 border border-blue-500/30 rounded-full px-1.5 py-0.5 text-[9px] font-bold tracking-wide flex items-center gap-1">
                                  <span className="w-1.5 h-1.5 border border-blue-400 border-t-transparent rounded-full animate-spin" />
                                  Analisando...
                                </span>
                              )}
                              {isScanComplete && (() => {
                                const sev = scanInfo?.severity;
                                const isError   = sev === 'ERROR';
                                const isPartial = sev === 'PARTIAL';
                                const isUnknown = !sev || sev === 'UNKNOWN' || sev === 'SKIPPED';
                                if (isError) return (
                                  <span className="badge-completo border rounded-full px-1.5 py-0.5 text-[9px] font-bold tracking-wide bg-gray-500/10 text-gray-400 border-gray-500/30">
                                    ⚙️ Erro no Scanner
                                  </span>
                                );
                                if (isUnknown && !isVuln) return (
                                  <span className="badge-completo border rounded-full px-1.5 py-0.5 text-[9px] font-bold tracking-wide bg-gray-500/10 text-gray-400 border-gray-500/30">
                                    — Sem dados
                                  </span>
                                );
                                return (
                                  <span className={`badge-completo border rounded-full px-1.5 py-0.5 text-[9px] font-bold tracking-wide ${isVuln ? 'bg-red-500/10 text-red-400 border-red-500/30' : isPartial ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30' : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'}`}>
                                    {isVuln ? `⚠️ Risco: ${sev || 'HIGH'}` : isPartial ? '⚠️ Parcial' : '🛡️ Scan Completo'}
                                  </span>
                                );
                              })()}
                            </div>
                          );
                        })()}
                      </div>
                    </div>

                    <div className="mt-4 pt-3 border-t border-white/5 space-y-2 mt-auto">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2 text-[11px] text-gray-400">
                          <User className="w-3 h-3 text-gray-500" />
                          <span className="truncate max-w-[100px]">{commit.author}</span>
                        </div>
                        <div className="flex items-center gap-2 text-[11px] text-gray-400">
                          <Clock className="w-3 h-3 text-gray-500" />
                          <span>{new Date(commit.date).toLocaleDateString('pt-BR')}</span>
                        </div>
                      </div>

                      <button
                        onClick={() => openIDEModal(commit.sha)}
                        className="w-full mt-3 flex items-center justify-center gap-2 bg-purple-600/20 hover:bg-purple-600/40 border border-purple-500/30 text-purple-300 py-1.5 rounded-lg text-xs font-semibold transition-colors"
                      >
                        <Search className="w-3.5 h-3.5" />
                        Ver mais detalhes
                      </button>
                    </div>

                    {!isMain && (
                      <div className="absolute -top-3 -right-3 bg-amber-500 text-[#060b13] text-[10px] font-bold px-2 py-1 rounded-lg border border-[#060b13] shadow-md pointer-events-none">
                        Pending Auth
                      </div>
                    )}

                    {/* Botão Context Menu */}
                    <button
                      className="absolute -right-2 top-1/2 -translate-y-1/2 w-6 h-6 rounded-full bg-slate-800 border border-white/10 flex items-center justify-center hover:bg-purple-600 hover:border-purple-500 transition-colors text-white/50 hover:text-white shadow-lg"
                      onClick={(e) => {
                        e.stopPropagation();
                        setOpenMenuSha(openMenuSha === commit.sha ? null : commit.sha);
                      }}
                    >
                      <ChevronRight className="w-3 h-3" />
                    </button>
                  </div>
                </div>

                {/* Dropdown Menu Extraído (Flutuando Fora do Card) */}
                {openMenuSha === commit.sha && (
                  <div
                    className="absolute bg-[#0b111a] border border-white/10 rounded-xl p-2 shadow-2xl flex flex-col gap-1 z-[100] w-56"
                    style={{ left: pos.x + 140, top: pos.y, transform: 'translate(0, -50%)' }}
                  >
                    <button className="flex items-center justify-between w-full text-left px-2 py-2 rounded-lg hover:bg-white/5 text-[13px] text-gray-300 hover:text-white transition-colors" onClick={() => toggleWidget(commit.sha, 'files')}>
                      <div className="flex items-center gap-2"><FileCode className="w-3.5 h-3.5 text-sky-400" /><span>Arquivos</span></div>
                      {widgets.includes('files') && <span className="w-1.5 h-1.5 rounded-full bg-sky-400" />}
                    </button>
                    <button className="flex items-center justify-between w-full text-left px-2 py-2 rounded-lg hover:bg-white/5 text-[13px] text-gray-300 hover:text-white transition-colors" onClick={() => generateCommitSummary(commit)}>
                      <div className="flex items-center gap-2"><BrainCircuit className="w-3.5 h-3.5 text-purple-400" /><span>Resumo IA</span></div>
                      {widgets.includes('ia') && <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />}
                    </button>
                    <button className="flex items-center justify-between w-full text-left px-2 py-2 rounded-lg hover:bg-white/5 text-[13px] text-gray-300 hover:text-white transition-colors" onClick={() => toggleWidget(commit.sha, 'details')}>
                      <div className="flex items-center gap-2"><Code className="w-3.5 h-3.5 text-emerald-400" /><span>Código Patch</span></div>
                      {widgets.includes('details') && <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />}
                    </button>
                    <div className="h-px bg-white/5 my-1" />
                    <button
                      className="flex items-center justify-between w-full text-left px-2 py-2 rounded-lg hover:bg-red-500/10 text-[13px] text-gray-300 hover:text-red-300 transition-colors"
                      onClick={() => expandSASTAnalysis(commit)}
                    >
                      <div className="flex items-center gap-2"><ShieldAlert className="w-3.5 h-3.5 text-red-400" /><span>Análise (SAST)</span></div>
                      {widgets.includes('sast') && <span className="w-1.5 h-1.5 rounded-full bg-red-400" />}
                    </button>
                  </div>
                )}

                {/* Renderizar Widgets do Commit */}
                {widgets.map(widget => {
                  const widgetId = `${commit.sha}-${widget}`;
                  const wPos = nodePositions[widgetId];
                  if (!wPos) return null;
                  const data = branchData[commit.sha];

                  return (
                    <div
                      key={widgetId}
                      className="no-pan absolute flex flex-col resize overflow-hidden w-72 min-h-[200px] h-auto max-h-[500px] bg-slate-900/90 border border-slate-700 rounded-lg shadow-xl text-sm"
                      style={{
                        left: wPos.x, top: wPos.y,
                        transform: 'translate(-50%, -50%)',
                        width: widget === 'details' ? 450 : 288,
                        zIndex: wPos.zIndex
                      }}
                      onMouseDown={() => {
                        maxZIndex.current += 1;
                        setNodePositions(p => ({ ...p, [widgetId]: { ...p[widgetId], zIndex: maxZIndex.current } }));
                      }}
                      onWheel={(e) => e.stopPropagation()}
                    >
                      {/* Cabeçalho de Arrasto (com botão fechar para SAST) */}
                      <div
                        className="cursor-move bg-black/40 p-1.5 flex items-center justify-between border-b border-white/5 hover:bg-black/60 transition-colors shrink-0"
                        onMouseDown={(e) => handleNodeDragStart(e, widgetId)}
                      >
                        <GripHorizontal className="w-4 h-4 text-gray-500" />
                        {widget === 'sast' ? (
                          <button
                            onMouseDown={(e) => e.stopPropagation()}
                            onClick={(e) => {
                              e.stopPropagation();
                              setActiveWidgets(prev => ({
                                ...prev,
                                [commit.sha]: (prev[commit.sha] || []).filter(w => w !== 'sast')
                              }));
                              setSastResults(prev => { const n = {...prev}; delete n[commit.sha]; return n; });
                            }}
                            className="ml-auto p-0.5 text-gray-600 hover:text-red-400 hover:bg-red-500/10 rounded transition-colors"
                            title="Fechar análise"
                          >
                            <X className="w-3 h-3" />
                          </button>
                        ) : widget === 'ia' ? (
                          <button
                            onMouseDown={(e) => e.stopPropagation()}
                            onClick={(e) => {
                              e.stopPropagation();
                              setActiveWidgets(prev => ({
                                ...prev,
                                [commit.sha]: (prev[commit.sha] || []).filter(w => w !== 'ia')
                              }));
                            }}
                            className="ml-auto p-0.5 text-gray-600 hover:text-purple-400 hover:bg-purple-500/10 rounded transition-colors"
                            title="Fechar Resumo IA"
                          >
                            <X className="w-3 h-3" />
                          </button>
                        ) : null}
                      </div>

                      {/* Corpo do Widget */}
                      <div className="flex-1 overflow-y-auto p-3 break-words relative custom-scrollbar flex flex-col">
                        {widget === 'files' && (
                          <div className="flex-1 flex flex-col border-sky-500/20">
                            <div className="flex items-center gap-2 mb-3 pb-2 border-b border-white/5 shrink-0">
                              <FileCode className="w-4 h-4 text-sky-400" />
                              <h4 className="text-sm font-semibold text-sky-100">Files Changed</h4>
                              <span className="ml-auto text-xs text-sky-500 bg-sky-500/10 px-2 py-0.5 rounded-full">{data?.files?.length || 0}</span>
                            </div>
                            <div className="flex-1 overflow-y-auto space-y-1 pr-1 custom-scrollbar">
                              {!data ? <p className="text-xs text-gray-500 animate-pulse">Carregando...</p> : data.files?.map(f => (
                                <div key={f.filename} className="text-[11px] flex items-center justify-between py-1.5 border-b border-white/5 last:border-0 hover:bg-white/5 px-2 rounded">
                                  <span className="truncate flex-1 text-gray-300" title={f.filename}>{f.filename}</span>
                                  <div className="flex items-center gap-2 shrink-0 ml-3">
                                    {f.additions > 0 && <span className="text-emerald-400 flex items-center"><PlusCircle className="w-3 h-3 mr-0.5" /> {f.additions}</span>}
                                    {f.deletions > 0 && <span className="text-red-400 flex items-center"><MinusCircle className="w-3 h-3 mr-0.5" /> {f.deletions}</span>}
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {widget === 'sast' && (() => {
                          const sast = sastResults[commit.sha];
                          const isFixed = fixedCommits[commit.sha];
                          const isVulnerable = sast?.vulnerable && !isFixed;
                          const isClean = sast?.vulnerable === false || isFixed;

                          return (
                            <div className={`flex-1 flex flex-col rounded-lg ${
                              isVulnerable
                                ? 'border border-red-500/50 bg-red-950/20'
                                : isClean
                                ? 'border border-emerald-500/40 bg-emerald-950/20'
                                : 'border border-slate-700'
                            }`}>
                              {/* Header do Card SAST */}
                              <div className={`flex items-center gap-2 mb-3 pb-2 border-b shrink-0 ${
                                isVulnerable ? 'border-red-500/30' : isClean ? 'border-emerald-500/30' : 'border-white/5'
                              }`}>
                                {sast?.loading ? (
                                  <><div className="w-4 h-4 border-2 border-orange-400 border-t-transparent rounded-full animate-spin" />
                                  <h4 className="text-sm font-semibold text-orange-200">Analisando...</h4></>
                                ) : isVulnerable ? (
                                  <><ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
                                  <h4 className="text-sm font-semibold text-red-200">Vuln. Detectada</h4>
                                  <span className="ml-auto text-[10px] font-bold px-2 py-0.5 rounded-full bg-red-500/20 text-red-400 border border-red-500/30">{sast?.severity}</span></>
                                ) : isFixed ? (
                                  <><ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                                  <h4 className="text-sm font-semibold text-emerald-200">Corrigido</h4>
                                  <span className="ml-auto text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">FIXED</span></>
                                ) : isClean ? (
                                  <><ShieldCheck className="w-4 h-4 text-sky-400 shrink-0" />
                                  <h4 className="text-sm font-semibold text-sky-200">Código Seguro</h4>
                                  <span className="ml-auto text-[10px] font-bold px-2 py-0.5 rounded-full bg-sky-500/20 text-sky-400 border border-sky-500/30">CLEAN</span></>
                                ) : (
                                  <><Zap className="w-4 h-4 text-orange-400" />
                                  <h4 className="text-sm font-semibold text-orange-100">Análise SAST</h4></>
                                )}
                              </div>

                              {/* Badges de ferramentas */}
                              {sast?.tools_used?.length > 0 && (
                                <div className="flex gap-1 mb-2 flex-wrap shrink-0">
                                  {sast.tools_used.map(t => (
                                    <span key={t} className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-800 border border-white/10 text-gray-400">{t}</span>
                                  ))}
                                </div>
                              )}

                              {/* Corpo: Dados técnicos ou IA */}
                              <div className="flex-1 overflow-y-auto custom-scrollbar">
                                {sast?.loading ? (
                                  <div className="text-xs text-gray-500 animate-pulse flex flex-col gap-2">
                                    <span>Executando Scanners (Semgrep/Trivy)...</span>
                                    <div className="flex gap-1">
                                      <div className="w-1.5 h-1.5 rounded-full bg-orange-500/50 animate-bounce" style={{ animationDelay: '0ms' }} />
                                      <div className="w-1.5 h-1.5 rounded-full bg-orange-500/50 animate-bounce" style={{ animationDelay: '150ms' }} />
                                      <div className="w-1.5 h-1.5 rounded-full bg-orange-500/50 animate-bounce" style={{ animationDelay: '300ms' }} />
                                    </div>
                                  </div>
                                ) : sast?.aiLoading ? (
                                  <div className="text-xs text-purple-400 animate-pulse flex flex-col gap-2 p-2 bg-purple-500/10 rounded-lg border border-purple-500/20">
                                    <div className="flex items-center gap-2">
                                      <Bot className="w-4 h-4 animate-spin-slow" />
                                      <span>IA Auditando o código...</span>
                                    </div>
                                  </div>
                                ) : sast?.analysis ? (
                                  isClean && !isFixed ? (
                                    <div className="flex flex-col h-full">
                                      <div className="flex items-center gap-1.5 mb-2 text-[10px] text-sky-400 font-semibold uppercase tracking-wider shrink-0">
                                        <ShieldCheck className="w-3 h-3" /> Prova Técnica de Segurança
                                      </div>
                                      <div className="text-[11px] text-sky-100/80 leading-relaxed whitespace-pre-wrap break-words text-justify max-h-64 overflow-y-auto pr-2 custom-scrollbar">
                                        {sast.analysis}
                                      </div>
                                    </div>
                                  ) : (
                                    <div className="text-[11px] text-gray-300 leading-relaxed whitespace-pre-wrap break-words text-justify max-h-64 overflow-y-auto pr-2 custom-scrollbar">
                                      {sast.analysis}
                                    </div>
                                  )
                                ) : (
                                  <div className="space-y-3">
                                    <div className="text-[11px] text-gray-400">
                                      {sast?.scanner_results && (Array.isArray(sast.scanner_results) ? sast.scanner_results.length > 0 : Object.keys(sast.scanner_results).length > 0) ? (
                                        <div className="space-y-2">
                                          <p className="font-semibold text-gray-300">Achados dos Scanners:</p>
                                          <ul className="list-disc pl-4 space-y-1">
                                            {Array.isArray(sast.scanner_results) 
                                              ? sast.scanner_results.map((r, i) => (
                                                  <li key={i}><span className="text-gray-300">[{r.tool}]</span> {r.file}: {r.rule}</li>
                                                ))
                                              : Object.entries(sast.scanner_results).map(([tool, data]) => (
                                                  <li key={tool}><span className="text-gray-300 capitalize">[{tool}]</span> Scan efetuado (Detalhes completos disponíveis no backend/console)</li>
                                                ))
                                            }
                                          </ul>
                                        </div>
                                      ) : (
                                        <p>Nenhuma vulnerabilidade detectada pelos scanners estruturais.</p>
                                      )}
                                    </div>
                                    <div className="flex flex-col gap-2">
                                      <button
                                        onClick={() => showFullScannerResults(sast.scanner_results)}
                                        className="w-full flex items-center justify-center gap-2 bg-slate-800/50 hover:bg-slate-700/50 border border-slate-600/50 text-gray-300 py-1.5 rounded-lg text-xs font-semibold transition-all duration-300"
                                      >
                                        📄 Ver Análise Completa
                                      </button>
                                      <button
                                        onClick={() => requestAIValidation(commit)}
                                        className="w-full flex items-center justify-center gap-2 bg-purple-600/20 hover:bg-purple-600/40 border border-purple-500/40 text-purple-300 py-1.5 rounded-lg text-xs font-semibold transition-all duration-300"
                                      >
                                        <Bot className="w-3.5 h-3.5" />
                                        Validação por IA
                                      </button>
                                    </div>
                                  </div>
                                )}
                              </div>

                              {/* Botão Marcar como Corrigido (apenas se vulnerável) */}
                              {isVulnerable && (
                                <button
                                  onClick={() => markAsFixed(commit.sha)}
                                  className="mt-3 w-full flex items-center justify-center gap-2 bg-emerald-600/20 hover:bg-emerald-600/40 border border-emerald-500/40 text-emerald-300 py-1.5 rounded-lg text-xs font-semibold transition-all duration-300 shrink-0"
                                >
                                  <ShieldCheck className="w-3.5 h-3.5" />
                                  ✅ Marcar como Corrigido
                                </button>
                              )}
                            </div>
                          );
                        })()}

                        {widget === 'ia' && (() => {
                          const summaryState = aiSummaries[commit.sha] || {};
                          return (
                          <div className="flex-1 flex flex-col border-purple-500/20">
                            <div className="flex items-center gap-2 mb-3 pb-2 border-b border-white/5 shrink-0">
                              <BrainCircuit className="w-4 h-4 text-purple-400" />
                              <h4 className="text-sm font-semibold text-purple-100">Análise IA</h4>
                            </div>
                            <div className="flex-1 overflow-y-auto text-xs text-gray-400 custom-scrollbar whitespace-pre-wrap leading-relaxed flex items-center justify-center text-center p-2">
                              {summaryState.loading ? (
                                <div className="flex flex-col items-center gap-2 text-purple-400 animate-pulse">
                                  <Bot className="w-6 h-6 animate-spin-slow" />
                                  <span>A IA está resumindo...</span>
                                </div>
                              ) : summaryState.text ? (
                                <div className="text-left w-full h-full text-[11px] text-gray-300">
                                  {summaryState.text}
                                </div>
                              ) : (
                                "Resumo não disponível."
                              )}
                            </div>
                          </div>
                          );
                        })()}

                        {widget === 'details' && (
                          <div className="flex-1 flex flex-col border-emerald-500/20 max-h-full">
                            <div className="flex items-center gap-2 mb-2 pb-2 border-b border-white/5 shrink-0">
                              <Code className="w-4 h-4 text-emerald-400" />
                              <h4 className="text-xs font-semibold text-emerald-100">Código Patch</h4>
                            </div>
                            <div className="flex-1 overflow-y-auto bg-[#040810] rounded-lg p-2 custom-scrollbar border border-white/5 relative">
                              {!data ? <p className="text-xs text-gray-500 animate-pulse">Carregando...</p> : data.files?.map((f, i) => (
                                <div key={i} className="mb-4 last:mb-0">
                                  <div className="text-[10px] text-sky-400 mb-1 sticky top-0 bg-[#040810] py-1 border-b border-white/5">{f.filename}</div>
                                  <pre className="text-[10px] font-mono leading-relaxed text-gray-400 whitespace-pre-wrap break-all">
                                    {f.patch?.split('\n').map((line, j) => {
                                      let color = "text-gray-400"; let bg = "";
                                      if (line.startsWith('+')) { color = "text-emerald-400"; bg = "bg-emerald-500/10"; }
                                      if (line.startsWith('-')) { color = "text-red-400"; bg = "bg-red-500/10"; }
                                      if (line.startsWith('@@')) color = "text-sky-400";
                                      return <div key={j} className={`${color} ${bg} px-1`}>{line}</div>
                                    }) || <span className="italic text-gray-600">No patch preview.</span>}
                                  </pre>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {/* Modal IDE (Revisão de Código) */}
      {selectedIDECommit && (
        <div className="fixed inset-0 z-[200] bg-black/90 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-11/12 max-w-6xl h-[85vh] flex flex-col bg-[#0b111a] border border-slate-700 rounded-xl overflow-hidden shadow-2xl animate-in fade-in zoom-in-95 duration-200">
            {/* Header */}
            <div className="shrink-0 h-16 border-b border-white/10 bg-[#0d1421] px-6 flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className="p-2 bg-purple-500/10 border border-purple-500/20 rounded-lg">
                  <Code className="w-5 h-5 text-purple-400" />
                </div>
                <div>
                  <h3 className="text-white font-semibold text-sm truncate max-w-lg">
                    {commits.find(c => c.sha === selectedIDECommit)?.message || "Detalhes do Commit"}
                  </h3>
                  <div className="flex items-center gap-3 text-xs text-gray-400 mt-0.5">
                    <span className="font-mono text-purple-400">{selectedIDECommit.substring(0, 7)}</span>
                    <span className="flex items-center gap-1"><User className="w-3 h-3" /> {commits.find(c => c.sha === selectedIDECommit)?.author}</span>
                  </div>
                </div>
              </div>
              <button
                onClick={() => setSelectedIDECommit(null)}
                className="p-2 text-gray-400 hover:text-white hover:bg-white/5 rounded-lg transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Split Pane */}
            <div className="flex-1 flex overflow-hidden">
              {/* Esquerda: Lista de Arquivos */}
              <div className="w-1/4 border-r border-white/5 bg-[#090e17] flex flex-col">
                <div className="p-3 border-b border-white/5 text-xs font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-2">
                  <FileCode className="w-4 h-4 text-sky-400" />
                  Arquivos Alterados
                </div>
                <div className="flex-1 overflow-y-auto custom-scrollbar p-2 space-y-1">
                  {ideLoading ? (
                    <p className="text-xs text-gray-500 animate-pulse p-2">Carregando arquivos...</p>
                  ) : (
                    branchData[selectedIDECommit]?.files?.map((f, i) => (
                      <button
                        key={i}
                        onClick={() => setSelectedIDEFile(f)}
                        className={`w-full text-left px-3 py-2 rounded-lg text-xs flex items-center justify-between group transition-colors
                          ${selectedIDEFile?.filename === f.filename ? 'bg-purple-500/20 text-purple-100 border border-purple-500/30' : 'text-gray-400 hover:bg-white/5 hover:text-gray-200 border border-transparent'}`}
                      >
                        <span className="truncate flex-1" title={f.filename}>{f.filename.split('/').pop()}</span>
                        <div className="flex items-center gap-2 shrink-0 ml-2 opacity-60 group-hover:opacity-100">
                          {f.additions > 0 && <span className="text-emerald-400">+{f.additions}</span>}
                          {f.deletions > 0 && <span className="text-red-400">-{f.deletions}</span>}
                        </div>
                      </button>
                    ))
                  )}
                </div>
              </div>

              {/* Direita: Editor de Código (Diff) */}
              <div className="w-3/4 bg-[#0d1117] flex flex-col relative">
                {selectedIDEFile ? (
                  <>
                    <div className="h-10 border-b border-white/5 bg-[#010409] flex items-center px-4 text-xs font-mono text-gray-400">
                      {selectedIDEFile.filename}
                    </div>
                    <div className="flex-1 overflow-auto custom-scrollbar p-4">
                      <pre className="text-[13px] font-mono leading-relaxed break-all whitespace-pre-wrap">
                        {selectedIDEFile.patch?.split('\n').map((line, j) => {
                          let color = "text-gray-300"; let bg = "";
                          if (line.startsWith('+')) { color = "text-emerald-300"; bg = "bg-emerald-900/30 block w-full"; }
                          else if (line.startsWith('-')) { color = "text-red-300"; bg = "bg-red-900/30 block w-full"; }
                          else if (line.startsWith('@@')) { color = "text-sky-300"; bg = "bg-sky-900/20 block w-full my-2 py-1 px-2 rounded"; }
                          return <div key={j} className={`${color} ${bg} px-1`}>{line}</div>
                        }) || <span className="italic text-gray-600">Este arquivo foi modificado, mas o patch não está disponível para visualização.</span>}
                      </pre>
                    </div>
                  </>
                ) : (
                  <div className="flex-1 flex items-center justify-center text-sm text-gray-500">
                    Selecione um arquivo à esquerda para revisar o código.
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Raw Scanner Data Modal */}
      {fullSastData && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="bg-[#0b111a] border border-white/10 rounded-2xl shadow-2xl w-full max-w-4xl flex flex-col overflow-hidden max-h-[90vh]">
            {/* Header */}
            <div className="h-14 border-b border-white/10 bg-[#060b13] flex items-center justify-between px-6 shrink-0">
              <div className="flex items-center gap-3">
                <div className="p-1.5 bg-emerald-500/10 rounded-lg border border-emerald-500/20">
                  <Code className="w-5 h-5 text-emerald-400" />
                </div>
                <h3 className="font-semibold text-white">Análise Completa (Raw Data)</h3>
              </div>
              <button
                onClick={() => setFullSastData(null)}
                className="p-2 text-gray-400 hover:text-white hover:bg-white/5 rounded-lg transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Body */}
            <div className="flex-1 overflow-y-auto custom-scrollbar p-6 space-y-6">
              {Object.entries(fullSastData).map(([tool, data]) => {
                const isEmpty = !data || (Array.isArray(data) && data.length === 0) || (typeof data === 'object' && Object.keys(data).length === 0);
                
                return (
                  <div key={tool} className={`border rounded-lg overflow-hidden ${isEmpty ? 'border-white/5 bg-white/5' : 'border-red-500/30 bg-red-950/10'}`}>
                    <div className={`px-4 py-2 border-b flex items-center justify-between ${isEmpty ? 'border-white/5' : 'border-red-500/30'}`}>
                      <h4 className={`font-mono text-sm capitalize font-bold ${isEmpty ? 'text-gray-400' : 'text-red-400'}`}>
                        {tool}
                      </h4>
                      {isEmpty ? (
                        <span className="text-[10px] bg-white/10 text-gray-400 px-2 py-0.5 rounded-full">CLEAN</span>
                      ) : (
                        <span className="text-[10px] bg-red-500/20 text-red-400 border border-red-500/30 px-2 py-0.5 rounded-full font-bold">ACHADOS ENCONTRADOS</span>
                      )}
                    </div>
                    {!isEmpty && (
                      <div className="p-4 bg-[#040810]">
                        <pre className="text-xs font-mono leading-relaxed overflow-x-auto custom-scrollbar">
                          <code className="text-emerald-400">
                            {JSON.stringify(data, null, 2)}
                          </code>
                        </pre>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

    </section>
  );
}
