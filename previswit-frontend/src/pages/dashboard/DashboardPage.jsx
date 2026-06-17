/**
 * PreviSwit — Page: Dashboard
 * Painel executivo com KPIs em tempo real e score de risco global.
 *
 * TODO: Implementar conteúdo completo desta página.
 * Esta é a estrutura base gerada pela arquitetura Clean Architecture do PreviSwit.
 */
import React from 'react';

export default function DashboardPage() {
  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Dashboard</h1>
          <p className="text-gray-400 text-sm mt-1">Painel executivo com KPIs em tempo real e score de risco global.</p>
        </div>
      </div>

      {/* Placeholder — substituir pelo conteúdo real da página */}
      <div className="flex items-center justify-center h-64 rounded-xl border border-dashed border-gray-700/50 bg-gray-900/30">
        <div className="text-center">
          <p className="text-gray-500 text-sm font-mono">[ Dashboard ]</p>
          <p className="text-gray-600 text-xs mt-2">Módulo em construção</p>
        </div>
      </div>
    </div>
  );
}
