import React from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { ShieldAlert, LayoutDashboard, Server, Workflow, TerminalSquare, BrainCircuit, TrendingUp, FileText, Puzzle, Settings, LogOut } from 'lucide-react';

export default function DashboardLayout({ setIsAuthenticated }) {
  const navigate = useNavigate();

  const handleLogout = () => {
    setIsAuthenticated(false);
    navigate('/login');
  };

  const navItems = [
    { id: 'overview', path: '/', label: 'Visão Geral', icon: <LayoutDashboard className="w-4 h-4" /> },
    { id: 'assets', path: '/assets', label: 'Ativos & Produtos', icon: <Server className="w-4 h-4" /> },
    { id: 'pipelines', path: '/pipelines', label: 'Engajamentos & Scans', icon: <Workflow className="w-4 h-4" /> },
    { id: 'findings', path: '/findings', label: 'Central de Findings', icon: <TerminalSquare className="w-4 h-4" /> },
    { id: 'ai', path: '/ai-insights', label: 'IA Insights', icon: <BrainCircuit className="w-4 h-4" /> },
    { id: 'risk', path: '/risk', label: 'Métricas de Risco', icon: <TrendingUp className="w-4 h-4" /> },
    { id: 'reports', path: '/reports', label: 'Relatórios', icon: <FileText className="w-4 h-4" /> },
    { id: 'integrations', path: '/integrations', label: 'Integrações', icon: <Puzzle className="w-4 h-4" /> },
    { id: 'settings', path: '/settings', label: 'Configurações', icon: <Settings className="w-4 h-4" /> },
  ];

  return (
    <div className="flex h-screen w-full bg-[#060b13] text-gray-200 overflow-hidden">
      
      {/* Sidebar */}
      <aside className="w-64 border-r border-white/5 flex flex-col justify-between bg-[#060b13]/80 backdrop-blur-xl shrink-0">
        <div>
          <div className="p-6 border-b border-white/5">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-6 h-6 text-blue-500" />
              <div>
                <h1 className="text-xl font-bold tracking-tight text-white leading-none">PreviSwit</h1>
                <p className="text-[10px] text-gray-500 font-medium uppercase tracking-widest mt-0.5">ASPM Console</p>
              </div>
            </div>
          </div>
          
          <nav className="p-3 space-y-0.5 overflow-y-auto" style={{ maxHeight: 'calc(100vh - 150px)' }}>
            {navItems.map(item => (
              <NavLink 
                key={item.id} 
                to={item.path}
                className={({ isActive }) => 
                  `w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-lg transition-all ${
                    isActive 
                      ? 'bg-blue-600/10 text-blue-400 border border-blue-500/20 shadow-[0_0_15px_rgba(59,130,246,0.15)]' 
                      : 'text-gray-400 hover:bg-white/5 hover:text-white border border-transparent'
                  }`
                }
              >
                {item.icon}
                {item.label}
              </NavLink>
            ))}
          </nav>
        </div>

        <div className="p-3 border-t border-white/5">
          <button 
            onClick={handleLogout}
            className="w-full flex items-center justify-center gap-2 px-3 py-2 text-sm font-medium text-gray-400 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-all"
          >
            <LogOut className="w-4 h-4" />
            Sair
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col overflow-hidden relative">
        {/* Background gradient effect */}
        <div className="absolute top-0 right-0 w-1/2 h-full bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-blue-900/10 via-transparent to-transparent pointer-events-none"></div>
        
        {/* Topbar / Content wrapper */}
        <div className="flex-1 overflow-y-auto p-8 relative z-10">
          <Outlet />
        </div>
      </main>

    </div>
  );
}
