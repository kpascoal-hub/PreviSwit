import React, { useState, useEffect, useRef } from 'react';
import { Play, Activity, AlertTriangle, Terminal } from 'lucide-react';

export default function EngagementsPage() {
  const [target, setTarget] = useState('');
  const [pipeline, setPipeline] = useState('all');
  const [status, setStatus] = useState('idle'); // idle, scanning, error, success
  const [errorMsg, setErrorMsg] = useState(null);
  
  // Terminal logs
  const [logs, setLogs] = useState([]);
  const logsEndRef = useRef(null);

  // Metrics
  const [metrics, setMetrics] = useState({ critical: 0, high: 0, medium: 0 });
  const [results, setResults] = useState(null);

  const wsRef = useRef(null);

  useEffect(() => {
    // Auto-scroll logs
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  useEffect(() => {
    // Conecta ao WebSocket do Dashboard
    wsRef.current = new WebSocket('ws://localhost:10000/ws/web_dashboard');

    wsRef.current.onopen = () => {
      addLog('Conectado ao servidor PreviSwit via WebSocket.', 'system');
    };

    wsRef.current.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        
        if (msg.action === 'LOG') {
          addLog(msg.message, 'info');
        } 
        else if (msg.action === 'SCAN_ERROR') {
          setStatus('error');
          setErrorMsg(msg.error || 'Erro desconhecido durante o scan.');
          addLog(`ERRO: ${msg.error}`, 'error');
        } 
        else if (msg.action === 'SCAN_RESULT') {
          setStatus('success');
          setResults(msg.data);
          addLog('Scan concluído com sucesso!', 'success');
          
          // Calcula métricas
          const findings = msg.data.findings_prioritized || [];
          const crit = findings.filter(f => f.severity?.toUpperCase() === 'CRITICAL').length;
          const hi = findings.filter(f => f.severity?.toUpperCase() === 'HIGH').length;
          const med = findings.filter(f => f.severity?.toUpperCase() === 'MEDIUM').length;
          
          setMetrics({ critical: crit, high: hi, medium: med });
        }
      } catch (err) {
        console.error('Falha ao processar mensagem WS', err);
      }
    };

    wsRef.current.onerror = () => {
      addLog('Erro na conexão WebSocket com o servidor.', 'error');
    };

    wsRef.current.onclose = () => {
      addLog('Conexão WebSocket fechada.', 'system');
    };

    return () => {
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  const addLog = (text, type = 'info') => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, { text, type, timestamp }]);
  };

  const handleScan = (e) => {
    e.preventDefault();
    if (!target) return;

    setStatus('scanning');
    setErrorMsg(null);
    setMetrics({ critical: 0, high: 0, medium: 0 });
    setResults(null);
    setLogs([]);
    addLog(`Iniciando scan no alvo: ${target} (Pipeline: ${pipeline})`, 'system');

    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        action: 'START_SCAN',
        target,
        pipeline
      }));
    } else {
      setStatus('error');
      setErrorMsg('Não conectado ao servidor WebSocket.');
      addLog('Falha ao enviar comando: WebSocket offline.', 'error');
    }
  };

  return (
    <div className="flex flex-col gap-6 max-w-6xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Engajamentos & Scans</h1>
          <p className="text-gray-400 text-sm mt-1">Orquestração e monitoramento de pipelines de segurança em tempo real.</p>
        </div>
      </div>

      {/* ERROR ALERT */}
      {status === 'error' && (
        <div className="glass-panel border-red-500/50 bg-red-500/10 p-4 flex items-start gap-3">
          <AlertTriangle className="w-6 h-6 text-red-500 shrink-0 mt-0.5" />
          <div>
            <h3 className="font-bold text-red-500">Falha no Scan</h3>
            <p className="text-red-400 text-sm mt-1">{errorMsg}</p>
          </div>
        </div>
      )}

      {/* CONTROLS */}
      <div className="glass-panel p-6">
        <form onSubmit={handleScan} className="flex flex-col md:flex-row gap-4">
          <div className="flex-1">
            <label className="block text-sm font-semibold text-gray-400 mb-2">URL Alvo</label>
            <input 
              type="url" 
              required
              placeholder="https://exemplo.com"
              value={target}
              onChange={e => setTarget(e.target.value)}
              className="w-full bg-[#03050a]/60 border border-gray-700/50 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-blue-500/80 transition-colors"
              disabled={status === 'scanning'}
            />
          </div>
          
          <div className="w-full md:w-64">
            <label className="block text-sm font-semibold text-gray-400 mb-2">Pipeline</label>
            <select 
              value={pipeline}
              onChange={e => setPipeline(e.target.value)}
              className="w-full bg-[#03050a]/60 border border-gray-700/50 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-blue-500/80 transition-colors appearance-none cursor-pointer"
              disabled={status === 'scanning'}
            >
              <option value="all">Todas (Completa)</option>
              <option value="1">1 - Tradicional (Recon + Scans)</option>
              <option value="2">2 - Agressiva (Crawling + DAST)</option>
              <option value="3">3 - Análise IA Local</option>
            </select>
          </div>

          <div className="flex items-end">
            <button 
              type="submit"
              disabled={status === 'scanning' || !target}
              className={`w-full md:w-auto px-8 py-3 rounded-lg font-bold flex items-center justify-center gap-2 transition-all ${
                status === 'scanning' 
                  ? 'bg-gray-700 text-gray-400 cursor-not-allowed' 
                  : 'bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-500/20'
              }`}
            >
              {status === 'scanning' ? (
                <><Activity className="w-5 h-5 animate-spin" /> Escaneando...</>
              ) : (
                <><Play className="w-5 h-5" /> Disparar Scan</>
              )}
            </button>
          </div>
        </form>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* LOGS TERMINAL */}
        <div className="lg:col-span-2 glass-panel p-0 overflow-hidden flex flex-col h-[500px]">
          <div className="bg-[#03050a] px-4 py-3 border-b border-gray-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-gray-400" />
              <span className="text-sm text-gray-400 font-mono">Agent Terminal</span>
            </div>
            <div className={`w-2 h-2 rounded-full ${wsRef.current?.readyState === WebSocket.OPEN ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`}></div>
          </div>
          <div className="flex-1 bg-black p-4 overflow-y-auto font-mono text-xs">
            {logs.length === 0 ? (
              <span className="text-gray-600 italic">Aguardando início...</span>
            ) : (
              logs.map((log, i) => (
                <div key={i} className={`mb-1 ${
                  log.type === 'error' ? 'text-red-400' : 
                  log.type === 'success' ? 'text-green-400' :
                  log.type === 'system' ? 'text-blue-400' : 'text-gray-300'
                }`}>
                  <span className="text-gray-600 mr-2">[{log.timestamp}]</span>
                  {log.text}
                </div>
              ))
            )}
            <div ref={logsEndRef} />
          </div>
        </div>

        {/* METRICS & RESULTS */}
        <div className="flex flex-col gap-6 h-[500px]">
          <div className="glass-panel p-6 flex-1 flex flex-col justify-center items-center text-center">
            <h3 className="text-gray-400 text-sm font-bold uppercase tracking-wider mb-2">Crítico</h3>
            <span className="text-6xl font-black text-red-500 drop-shadow-[0_0_15px_rgba(239,68,68,0.5)]">
              {metrics.critical}
            </span>
          </div>
          
          <div className="glass-panel p-6 flex-1 flex flex-col justify-center items-center text-center">
            <h3 className="text-gray-400 text-sm font-bold uppercase tracking-wider mb-2">Alto</h3>
            <span className="text-6xl font-black text-orange-500 drop-shadow-[0_0_15px_rgba(245,158,11,0.5)]">
              {metrics.high}
            </span>
          </div>

          <div className="glass-panel p-6 flex-1 flex flex-col justify-center items-center text-center">
            <h3 className="text-gray-400 text-sm font-bold uppercase tracking-wider mb-2">Médio</h3>
            <span className="text-6xl font-black text-blue-400 drop-shadow-[0_0_15px_rgba(59,130,246,0.5)]">
              {metrics.medium}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
