import React, { useState, useEffect } from 'react';

const API = '/api/v1';

export default function AssetsPage() {
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);

  const fetchAssets = async () => {
    setLoading(true);
    setError(false);
    try {
      const res = await fetch(API + '/assets/');
      if (res.ok) {
        const data = await res.json();
        setAssets(data.assets ?? []);   // ← unwrap o array correto
      } else {
        setError(true);
      }
    } catch (e) {
      setError(true);
    }
    setLoading(false);
  };

  useEffect(() => {
    fetchAssets();
  }, []);

  const total = assets.length;
  const critical = assets.filter(a => a.criticality === 'CRITICAL').length;
  
  return (
    <div className="flex flex-col h-full">
      <div className="mb-6">
        <h2 className="text-xl font-semibold text-white">Ativos & Produtos</h2>
        <p className="text-sm text-gray-500 mt-1">Inventário de ativos digitais e produtos enriquecido por IA.</p>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="bg-[#0d1421] border border-white/5 rounded-xl p-5">
          <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Total de Ativos</p>
          <p className="text-3xl font-bold text-white">{loading ? '...' : total}</p>
        </div>
        <div className="bg-[#0d1421] border border-white/5 rounded-xl p-5">
          <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Ativos Críticos</p>
          <p className="text-3xl font-bold text-red-400">{loading ? '...' : critical}</p>
        </div>
        <div className="bg-[#0d1421] border border-white/5 rounded-xl p-5">
          <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Superfície de Ataque</p>
          <p className="text-3xl font-bold text-orange-400">{loading ? '...' : total}</p>
        </div>
      </div>

      <div className="flex-1 min-h-0 flex flex-col bg-[#0d1421] border border-white/5 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-white/5 flex items-center justify-between shrink-0">
          <p className="text-sm font-semibold text-gray-300">Lista de Ativos</p>
          <button onClick={fetchAssets} className="text-xs bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 px-3 py-1.5 rounded-lg hover:bg-indigo-600/40 transition-colors">
            ↻ Atualizar
          </button>
        </div>
        <div className="p-4 overflow-y-auto flex-1">
          {loading && <p className="text-gray-500 text-sm text-center py-12">Carregando...</p>}
          {error && !loading && <p className="text-red-400 text-sm text-center py-12">Erro ao conectar com a API.</p>}
          {!loading && !error && assets.length === 0 && <p className="text-gray-600 text-sm text-center py-12">Nenhum ativo cadastrado ainda.</p>}
          {!loading && !error && assets.length > 0 && (
            <div className="space-y-1">
              {assets.map((a, i) => (
                <div key={i} className="flex items-center justify-between py-3 border-b border-white/5 px-2">
                  <div>
                    <p className="text-sm text-white font-medium">{a.name}</p>
                    <p className="text-xs text-gray-500">{a.asset_type || 'N/A'} · {a.host || ''}</p>
                  </div>
                  <span className={`text-xs px-2 py-1 rounded-full border ${a.criticality === 'CRITICAL' ? 'bg-red-500/10 text-red-400 border-red-500/20' : 'bg-gray-500/10 text-gray-400 border-gray-500/20'}`}>
                    {a.criticality || 'N/A'}
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
