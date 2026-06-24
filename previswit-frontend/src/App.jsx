import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';

// Layout
import DashboardLayout from './components/layout/DashboardLayout';

// Pages
import LoginPage from './pages/login/LoginPage';
import DashboardPage from './pages/dashboard/DashboardPage';
import AssetsPage from './pages/assets/AssetsPage';
import AssetsCategoryPage from './pages/assets/AssetsCategoryPage';
import RepositoriesPage from './pages/assets/RepositoriesPage';
import EngagementsPage from './pages/engagements/EngagementsPage';
import FindingsPage from './pages/findings/FindingsPage';
import AiInsightsPage from './pages/ai-insights/AiInsightsPage';
import RiskPage from './pages/risk/RiskPage';
import ReportsPage from './pages/reports/ReportsPage';
import IntegrationsPage from './pages/integrations/IntegrationsPage';
import SettingsPage from './pages/settings/SettingsPage';

export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  return (
    <Router>
      <Routes>
        {/* Rota pública */}
        <Route
          path="/login"
          element={<LoginPage setIsAuthenticated={setIsAuthenticated} />}
        />

        {/* Rotas protegidas (Dashboard) */}
        <Route
          path="/"
          element={
            isAuthenticated ? (
              <DashboardLayout setIsAuthenticated={setIsAuthenticated} />
            ) : (
              <Navigate to="/login" replace />
            )
          }
        >
          <Route index element={<DashboardPage />} />

          {/* Ativos & Produtos — visão geral + sub-categorias */}
          <Route path="assets" element={<AssetsPage />} />
          <Route path="assets/repositories" element={<RepositoriesPage />} />
          <Route path="assets/cloud"        element={<AssetsCategoryPage />} />
          <Route path="assets/containers"   element={<AssetsCategoryPage />} />
          <Route path="assets/vms"          element={<AssetsCategoryPage />} />
          <Route path="assets/domains"      element={<AssetsCategoryPage />} />

          <Route path="pentest"     element={<EngagementsPage />} />
          <Route path="findings"    element={<FindingsPage />} />
          <Route path="ai-insights" element={<AiInsightsPage />} />
          <Route path="risk"        element={<RiskPage />} />
          <Route path="reports"     element={<ReportsPage />} />
          <Route path="integrations" element={<IntegrationsPage />} />
          <Route path="settings"    element={<SettingsPage />} />
        </Route>

        {/* Fallback */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Router>
  );
}
