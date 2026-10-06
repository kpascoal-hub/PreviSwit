/*
 * PreviSwit AI-ASPM
 * Copyright (C) 2026 PreviSwit Team
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
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
import CloudPage from './pages/assets/CloudPage';
import ContainersPage from './pages/assets/ContainersPage';
import DomainsPage from './pages/assets/DomainsPage';
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
          <Route path="assets/cloud"        element={<CloudPage />} />
          <Route path="assets/containers"   element={<ContainersPage />} />
          <Route path="assets/vms"          element={<AssetsCategoryPage />} />
          <Route path="assets/domains"      element={<DomainsPage />} />

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
