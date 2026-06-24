# Estrutura de Páginas (`src/pages`)

Este diretório contém as páginas principais da aplicação SPA do **PreviSwit (AI-ASPM)**. Cada subdiretório corresponde a uma seção ou funcionalidade chave acessível pelo menu lateral (Sidebar) ou pelas rotas definidas em `App.jsx`.

## 📂 Organização dos Diretórios

Abaixo está o descritivo de cada módulo para facilitar a navegação e a manutenção pelo time:

* **`login/`**
  * Página pública de autenticação do usuário.

* **`dashboard/`**
  * Visão Geral. A tela inicial (home) carregada após o login. Apresenta um painel de indicadores principais.

* **`assets/`**
  * Gestão de **Ativos & Produtos**.
  * `AssetsPage.jsx`: Página de resumo (Summary) exibindo KPIs e os cards das categorias dinamicamente via `/api/v1/assets/summary`.
  * `RepositoriesPage.jsx`: Página **dedicada** para a gestão de Repositórios de Código, preparada para a injeção de dados via API.
  * `AssetsCategoryPage.jsx`: Página genérica para renderizar outras categorias de ativos (Cloud, Contêineres, VMs, Domínios) consumindo `/api/v1/assets/category/{type}`.

* **`engagements/`**
  * Gestão de **Pentest** (Engajamentos & Scans).
  * `EngagementsPage.jsx`: Orquestração e monitoramento de scans (como DAST) com ataques ativos a alvos em tempo real.

* **`findings/`**
  * **Central de Findings**.
  * Lista unificada e detalhada de vulnerabilidades (SAST, DAST, Secrets, IaC) já normalizadas pelo motor do PreviSwit.

* **`ai-insights/`**
  * **IA Insights**.
  * Recomendações e análises aprofundadas geradas por Inteligência Artificial para remediação inteligente das falhas.

* **`risk/`**
  * **Métricas de Risco**.
  * Dashboards voltados para o score de risco, quantificação do impacto e relatórios gerenciais sobre a superfície de ataque.

* **`integrations/`**
  * **Integrações**.
  * Configurações de conexões externas e testes dos parsers internos (Semgrep, Gitleaks, Checkov, etc.). Permite simular ou configurar as injeções de JSON.

* **`reports/`**
  * Geração e exportação de relatórios de conformidade e segurança.

* **`settings/`**
  * Configurações de sistema, perfil de usuário e ajustes gerais da plataforma.

---

## 🏗️ Padrão Arquitetural

1. **Separação de Responsabilidades:** Cada funcionalidade do sistema deve ter sua própria pasta aqui dentro.
2. **Componentes Puros:** Esses arquivos devem focar apenas na **composição visual** e chamadas de API (`fetch`). Evite criar regras de negócio complexas aqui; delegue as regras de processamento (parsing, normalização) sempre para o **Backend (FastAPI)**.
3. **Sem Dados Falsos (Mock):** O código deve sempre consumir os dados do servidor. Onde houver falta de dados, devemos exibir um "Empty State" estruturado.
4. **Estilo (Design System):** Todas as telas devem seguir o padrão estético **Cyber Dark Enterprise**, mantendo coesão visual e classes estruturais via Tailwind CSS.
