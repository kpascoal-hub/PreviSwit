import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { ArrowLeft, GitCommit, User, Clock, ShieldAlert, ChevronRight, FileCode, BrainCircuit, Code, PlusCircle, MinusCircle, GitPullRequest, GripHorizontal, X, Filter, Search } from 'lucide-react';

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

  // Filters State
  const [isFilterOpen, setIsFilterOpen] = useState(false);
  const [draftFilters, setDraftFilters] = useState({ author: '', date: '', sort: 'desc' });
  const [activeFilters, setActiveFilters] = useState({ author: '', date: '', sort: 'desc' });

  // IDE Modal State
  const [selectedIDECommit, setSelectedIDECommit] = useState(null);
  const [selectedIDEFile, setSelectedIDEFile] = useState(null);
  const [ideLoading, setIdeLoading] = useState(false);

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
        setCommits(data.commits ?? []);

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
        {/* Container Pai dos Filtros Flutuantes */}
        <div
          className="absolute top-4 left-4 z-50 flex flex-col gap-2 no-pan cursor-default"
          onMouseDown={(e) => e.stopPropagation()}
          onWheel={(e) => e.stopPropagation()}
        >
          {/* Botão Retrátil */}
          <button
            onClick={() => setIsFilterOpen(!isFilterOpen)}
            className="w-10 h-10 rounded-full bg-[#0d1421] border border-slate-700 shadow-xl flex items-center justify-center text-gray-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <Filter className="w-5 h-5" />
          </button>

          {/* Painel de Filtros */}
          {isFilterOpen && (
            <div className="bg-slate-900/90 backdrop-blur-md border border-slate-700 p-4 rounded-xl shadow-2xl flex flex-col gap-4 animate-in fade-in slide-in-from-top-2 w-64">
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
                  className={`no-pan absolute flex flex-col resize overflow-hidden w-72 min-h-[200px] h-auto max-h-[500px] bg-slate-900/90 rounded-lg shadow-xl text-sm
                             ${isMain ? 'border border-slate-700 hover:shadow-purple-500/10' : 'border border-amber-500/40 hover:shadow-amber-500/10'}`}
                  style={{ left: pos.x, top: pos.y, transform: 'translate(-50%, -50%)', zIndex: pos.zIndex }}
                  onMouseDown={() => {
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
                    <button className="flex items-center justify-between w-full text-left px-2 py-2 rounded-lg hover:bg-white/5 text-[13px] text-gray-300 hover:text-white transition-colors" onClick={() => toggleWidget(commit.sha, 'ia')}>
                      <div className="flex items-center gap-2"><BrainCircuit className="w-3.5 h-3.5 text-purple-400" /><span>Resumo IA</span></div>
                      {widgets.includes('ia') && <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />}
                    </button>
                    <button className="flex items-center justify-between w-full text-left px-2 py-2 rounded-lg hover:bg-white/5 text-[13px] text-gray-300 hover:text-white transition-colors" onClick={() => toggleWidget(commit.sha, 'details')}>
                      <div className="flex items-center gap-2"><Code className="w-3.5 h-3.5 text-emerald-400" /><span>Código Patch</span></div>
                      {widgets.includes('details') && <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />}
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
                      {/* Cabeçalho de Arrasto */}
                      <div
                        className="cursor-move bg-black/40 p-1.5 flex items-center justify-center border-b border-white/5 hover:bg-black/60 transition-colors shrink-0"
                        onMouseDown={(e) => handleNodeDragStart(e, widgetId)}
                      >
                        <GripHorizontal className="w-4 h-4 text-gray-500" />
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

                        {widget === 'ia' && (
                          <div className="flex-1 flex flex-col border-purple-500/20">
                            <div className="flex items-center gap-2 mb-3 pb-2 border-b border-white/5 shrink-0">
                              <BrainCircuit className="w-4 h-4 text-purple-400" />
                              <h4 className="text-sm font-semibold text-purple-100">Análise IA</h4>
                            </div>
                            <div className="flex-1 overflow-y-auto text-xs text-gray-400 custom-scrollbar whitespace-pre-wrap leading-relaxed flex items-center justify-center text-center">
                              Integração LLM pendente. Em breve, IA resumirá o impacto.
                            </div>
                          </div>
                        )}

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
    </section>
  );
}
