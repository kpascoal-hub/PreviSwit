import React, { useState, useEffect, useRef } from 'react';
import { Play, Activity, AlertTriangle, ShieldAlert, CheckCircle, Terminal } from 'lucide-react';

export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loginUser, setLoginUser] = useState('');
  const [loginPass, setLoginPass] = useState('');
  const [loginError, setLoginError] = useState(false);

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

  const handleLogin = (e) => {
    e.preventDefault();
    if (loginUser === 'admin' && loginPass === 'admin') {
      setIsAuthenticated(true);
      setLoginError(false);
    } else {
      setLoginError(true);
    }
  };

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen flex items-center justify-center relative overflow-hidden bg-[#060b13]">
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-blue-900/20 via-[#060b13] to-[#060b13]"></div>
        <div className="glass-panel w-full max-w-md p-10 relative z-10">
          <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-blue-600 to-emerald-500 rounded-t-xl"></div>
          <div className="mb-10 text-center">
            <h1 className="text-3xl font-bold text-white mb-2">PreviSwit ASPM</h1>
            <p className="text-xs text-gray-400 uppercase tracking-widest font-semibold">Autenticação do Sistema</p>
          </div>
          
          {loginError && (
            <div className="mb-6 p-4 rounded bg-red-500/10 border border-red-500/30 text-red-400 text-sm text-center font-medium">
              Credenciais inválidas.
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-6">
            <div>
              <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Identificador</label>
              <input type="text" required value={loginUser} onChange={(e)=>setLoginUser(e.target.value)}
                className="w-full bg-[#03050a]/60 border border-gray-700/50 rounded px-4 py-3 text-white focus:outline-none focus:border-blue-500/80" />
            </div>
            <div>
              <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Chave de Segurança</label>
              <input type="password" required value={loginPass} onChange={(e)=>setLoginPass(e.target.value)}
                className="w-full bg-[#03050a]/60 border border-gray-700/50 rounded px-4 py-3 text-white focus:outline-none focus:border-blue-500/80" />
            </div>
            <button type="submit" className="w-full bg-blue-600 text-white font-bold py-3 rounded hover:bg-blue-500 transition-colors mt-4 shadow-lg shadow-blue-900/20">
              Acessar Plataforma
            </button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen p-6 md:p-10 flex flex-col gap-8 max-w-7xl mx-auto">
      
      {/* HEADER */}
      <header className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ShieldAlert className="w-10 h-10 text-primary" />
          <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-emerald-400">
            PreviSwit AI-ASPM
          </h1>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <div className={`w-3 h-3 rounded-full ${wsRef.current?.readyState === WebSocket.OPEN ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`}></div>
            <span className="text-sm text-gray-400">WebSocket Status</span>
          </div>
          <button 
            onClick={() => setIsAuthenticated(false)}
            className="text-sm text-gray-400 hover:text-white px-3 py-1 border border-gray-700 rounded transition-colors">
            Sair
          </button>
        </div>
      </header>

      {/* ERROR ALERT */}
      {status === 'error' && (
        <div className="glass-panel border-danger/50 bg-danger/10 p-4 flex items-start gap-3">
          <AlertTriangle className="w-6 h-6 text-danger shrink-0 mt-0.5" />
          <div>
            <h3 className="font-bold text-danger">Falha no Scan</h3>
            <p className="text-danger/80 text-sm mt-1">{errorMsg}</p>
          </div>
        </div>
      )}

      {/* CONTROLS */}
      <div className="glass-panel p-6">
        <form onSubmit={handleScan} className="flex flex-col md:flex-row gap-4">
          <div className="flex-1">
            <label className="block text-sm text-gray-400 mb-2">URL Alvo</label>
            <input 
              type="url" 
              required
              placeholder="https://exemplo.com"
              value={target}
              onChange={e => setTarget(e.target.value)}
              className="w-full bg-background border border-gray-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-primary transition-colors"
              disabled={status === 'scanning'}
            />
          </div>
          
          <div className="w-full md:w-64">
            <label className="block text-sm text-gray-400 mb-2">Pipeline</label>
            <select 
              value={pipeline}
              onChange={e => setPipeline(e.target.value)}
              className="w-full bg-background border border-gray-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-primary transition-colors appearance-none cursor-pointer"
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
                  : 'bg-primary hover:bg-blue-600 text-white shadow-lg shadow-blue-500/20'
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

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        
        {/* LOGS TERMINAL */}
        <div className="lg:col-span-2 glass-panel p-0 overflow-hidden flex flex-col h-[500px]">
          <div className="bg-gray-900 px-4 py-3 border-b border-gray-800 flex items-center gap-2">
            <Terminal className="w-4 h-4 text-gray-400" />
            <span className="text-sm text-gray-400 font-mono">Agent Terminal</span>
          </div>
          <div className="flex-1 bg-black p-4 overflow-y-auto font-mono text-sm">
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
        <div className="flex flex-col gap-4 h-[500px]">
          <div className="glass-panel p-6 flex-1 flex flex-col justify-center items-center text-center">
            <h3 className="text-gray-400 text-sm font-bold uppercase tracking-wider mb-2">Crítico</h3>
            <span className="text-6xl font-black text-danger drop-shadow-[0_0_15px_rgba(239,68,68,0.5)]">
              {metrics.critical}
            </span>
          </div>
          
          <div className="glass-panel p-6 flex-1 flex flex-col justify-center items-center text-center">
            <h3 className="text-gray-400 text-sm font-bold uppercase tracking-wider mb-2">Alto</h3>
            <span className="text-6xl font-black text-accent drop-shadow-[0_0_15px_rgba(245,158,11,0.5)]">
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
