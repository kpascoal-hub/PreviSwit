import React from 'react';

export default function IntegrationsPage() {
  const integrations = [
    { name: 'GitHub Actions', desc: 'CI/CD Pipeline', icon: '🔗', active: true, color: 'indigo' },
    { name: 'Jira', desc: 'Gestão de Issues', icon: '🎫', active: false, color: 'blue' },
    { name: 'Slack', desc: 'Alertas em Tempo Real', icon: '💬', active: false, color: 'purple' },
    { name: 'Nuclei', desc: 'Scanner de Vulnerabilidades', icon: '🔍', active: true, color: 'orange' },
    { name: 'Trivy', desc: 'Scanner de Containers', icon: '🛡️', active: true, color: 'red' },
    { name: 'Nmap', desc: 'Scanner de Rede', icon: '🗺️', active: true, color: 'green' },
  ];

  return (
    <div className="flex flex-col h-full">
      <div className="mb-6">
        <h2 className="text-xl font-semibold text-white">Integrações</h2>
        <p className="text-sm text-gray-500 mt-1">Ferramentas de scan, CI/CD, ITSM e notificações.</p>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {integrations.map((intg, idx) => (
          <div key={idx} className="bg-[#0d1421] border border-white/5 rounded-xl p-5 flex items-center gap-4">
            <div className={`w-10 h-10 rounded-lg bg-${intg.color}-600/20 border border-${intg.color}-500/30 flex items-center justify-center text-lg`}>
              {intg.icon}
            </div>
            <div>
              <p className="text-sm font-semibold text-white">{intg.name}</p>
              <p className="text-xs text-gray-500">{intg.desc}</p>
            </div>
            {intg.active ? (
              <span className="ml-auto text-xs bg-green-500/15 text-green-400 border border-green-500/25 px-2 py-1 rounded-full">Ativo</span>
            ) : (
              <span className="ml-auto text-xs bg-gray-500/15 text-gray-400 border border-gray-500/25 px-2 py-1 rounded-full">Inativo</span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
