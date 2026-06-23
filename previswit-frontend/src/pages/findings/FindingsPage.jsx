import React, { useState, useEffect } from 'react';

const API = '/api/v1';

export default function FindingsPage() {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);
  const [counts, setCounts] = useState({ CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 });

  const fetchFindings = async () => {
    setLoading(true);
    setError(false);
    try {
      const res = await fetch(API + '/findings/');
      if (res.ok) {
        const data = await res.json();
        setFindings(data.findings ?? []);
        
        const newCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
        (data.findings ?? []).forEach(f => {
          if (newCounts[f.severity] !== undefined) newCounts[f.severity]++;
        });
        setCounts(newCounts);
      } else {
        setError(true);
      }
    } catch (e) {
      setError(true);
    }
    setLoading(false);
  };

  useEffect(() => {
    fetchFindings();
  }, []);

  const getSeverityStyle = (severity) => {
    const styles = {
      CRITICAL: 'text-red-400 border-red-500/20 bg-red-500/10',
      HIGH: 'text-orange-400 border-orange-500/20 bg-orange-500/10',
      MEDIUM: 'text-yellow-400 border-yellow-500/20 bg-yellow-500/10',
      LOW: 'text-green-400 border-green-500/20 bg-green-500/10',
      INFO: 'text-blue-400 border-blue-500/20 bg-blue-500/10'
    };
    return styles[severity] || styles.INFO;
  };

  return (
    <div className="flex flex-col h-full">
      <div className="mb-6">
        <h2 className="text-xl font-semibold text-white">Central de Findings</h2>
        <p className="text-sm text-gray-500 mt-1">Triagem unificada de vulnerabilidades com deduplicação por IA.</p>
      </div>
      
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-6">
        <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-4 text-center">
          <p className="text-xs text-red-400 uppercase tracking-wider mb-1">Crítico</p>
          <p className="text-2xl font-bold text-red-300">{loading ? '...' : counts.CRITICAL}</p>
        </div>
        <div className="bg-orange-500/10 border border-orange-500/20 rounded-xl p-4 text-center">
          <p className="text-xs text-orange-400 uppercase tracking-wider mb-1">Alto</p>
          <p className="text-2xl font-bold text-orange-300">{loading ? '...' : counts.HIGH}</p>
        </div>
        <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-xl p-4 text-center">
          <p className="text-xs text-yellow-400 uppercase tracking-wider mb-1">Médio</p>
          <p className="text-2xl font-bold text-yellow-300">{loading ? '...' : counts.MEDIUM}</p>
        </div>
        <div className="bg-green-500/10 border border-green-500/20 rounded-xl p-4 text-center">
          <p className="text-xs text-green-400 uppercase tracking-wider mb-1">Baixo</p>
          <p className="text-2xl font-bold text-green-300">{loading ? '...' : counts.LOW}</p>
        </div>
        <div className="bg-blue-500/10 border border-blue-500/20 rounded-xl p-4 text-center">
          <p className="text-xs text-blue-400 uppercase tracking-wider mb-1">Info</p>
          <p className="text-2xl font-bold text-blue-300">{loading ? '...' : counts.INFO}</p>
        </div>
      </div>

      <div className="flex-1 min-h-0 flex flex-col bg-[#0d1421] border border-white/5 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-white/5 flex items-center justify-between shrink-0">
          <p className="text-sm font-semibold text-gray-300">Findings Abertos</p>
          <button onClick={fetchFindings} className="text-xs bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 px-3 py-1.5 rounded-lg hover:bg-indigo-600/40 transition-colors">
            ↻ Atualizar
          </button>
        </div>
        <div className="p-4 overflow-y-auto flex-1">
          {loading && <p className="text-gray-500 text-sm text-center py-12">Carregando...</p>}
          {error && !loading && <p className="text-red-400 text-sm text-center py-12">Erro ao conectar com a API.</p>}
          {!loading && !error && findings.length === 0 && <p className="text-gray-600 text-sm text-center py-12">Nenhum finding cadastrado ainda.</p>}
          {!loading && !error && findings.length > 0 && (
            <div className="space-y-1">
              {findings.map((f, i) => (
                <div key={i} className="flex items-center justify-between py-3 border-b border-white/5 px-2">
                  <div className="flex-1 min-w-0 pr-4">
                    <p className="text-sm text-white font-medium truncate">{f.title}</p>
                    <p className="text-xs text-gray-500">{f.tool || 'Manual'} · {f.status || 'open'}</p>
                  </div>
                  <span className={`shrink-0 text-xs px-2 py-1 rounded-full border ${getSeverityStyle(f.severity)}`}>
                    {f.severity}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
