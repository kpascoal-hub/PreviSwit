# PreviSwit Frontend Architecture

Bem-vindo à pasta `src` do frontend da PreviSwit (AI-ASPM).

Nesta pasta ficam contidos os componentes e lógicas que estruturam nossa SPA em React + Tailwind. O destaque desta camada é a nossa arquitetura de **Risk Graph (Grafo de Risco/Canvas Infinito)** localizada em `pages/assets/RiskGraphCanvas.jsx`, e a nova **Central de Relatórios e Conformidade** em `pages/reports/ReportsPage.jsx`.

---

## Risk Graph (Infinite Canvas)

O Risk Graph é uma representação visual avançada, projetada no estilo "Mapa Mental", que mapeia a árvore da vida dos Commits e Pull Requests de um repositório GitHub sem depender de pesadas bibliotecas gráficas externas.

### Core Features
- **Design Cyber Dark:** Estilos minimalistas baseados em Tailwind, focado numa temática "hacker/corporativa" (`bg-[#060b13]`).
- **Bring Your Own Token (BYOT / BYOK):** Toda requisição para a API utiliza `X-GitHub-Token` e `X-Gemini-Key` salvos na sessão, garantindo escalabilidade e segurança por chave própria do analista.
- **Navegação de Câmera:** Pan & Zoom integrados e fluidos através do mouse (inspirados em Figma/Miro).
- **Drag & Drop Isolado:** Todos os "Cards" no canvas podem ser reposicionados livremente. O motor calcula os vetores de movimento com base na escala de zoom atual.
- **SVG Dinâmicos:** As conexões entre "Nós Pai" e "Filhos" são desenhadas globalmente através de `<svg>` sobreposto no fundo. Reagem instantaneamente ao deslocamento de qualquer card.

### Ferramentas de Auditoria (Cards/Widgets)
- **Filtros Retráteis:** Menu de funil no canto superior do mapa — filtra por Autor, Data Inicial e sentido da linha do tempo. Usa sistema Draft/Active States (filtro só reage ao DOM ao apertar "Salvar").
- **Análise SAST por Commit:** Ao clicar em "Análise (SAST)" no menu de contexto de qualquer commit, o sistema clona o repositório no backend, executa **Semgrep**, **Trivy**, **Gitleaks** e **Checkov** e retorna os resultados consolidados em um card filho.
- **Validação por IA (Gemini):** Após a análise SAST, o analista pode acionar a validação por IA. O Gemini atua como Auditor Sênior de AppSec e gera um relatório técnico ou executivo baseado nos achados reais dos scanners.
- **Resumo da IA:** O botão "Resumo IA" no menu de contexto de cada commit aciona o endpoint `POST /api/v1/ai/summarize-commit`, que pede ao Gemini um resumo de até 2 parágrafos sobre o que foi feito naquele commit e o impacto arquitetural da mudança.
- **Deep Dive Modal (Revisão de Código):** Inspecione o Diff/Patch do código nativamente na aplicação via Split-Pane com explorador de arquivos.
- **Micro-interações:** Barras de scroll redesenhadas globalmente (perfil Dark) e estados de carregamento com spinners e animações para todas as ações assíncronas.

### Ponte para a Central de Relatórios
Após um scan SAST ou validação de IA, o `RiskGraphCanvas` pode publicar o laudo automaticamente na Central de Relatórios via **API pública global**:

```js
// Disponível em qualquer componente React enquanto a página de Relatórios estiver montada
if (window.previswit?.reports?.receive) {
  window.previswit.reports.receive({
    title:            `Auditoria SAST — Commit ${sha.slice(0, 7)}`,
    target:           `commit:${sha}`,
    target_label:     `${sha.slice(0, 7)} — ${branchName}`,
    type:             'SAST Técnico',
    standard:         'OWASP Top 10 / CWE',
    risk:             data.vulnerable ? 'HIGH' : 'CLEAN',
    compliance_model: 'TECNICO',       // ISO_27001 | EXECUTIVO | TECNICO
    scan_data:        data.scanner_results,
  });
}
```

---

## Central de Relatórios e Conformidade (`pages/reports/ReportsPage.jsx`)

A Central de Relatórios é a interface de **comando executivo** da plataforma. Ela lista, filtra, baixa e gerencia todos os laudos de segurança gerados pelas análises SAST e pela IA.

### Arquitetura da Página

A página é **100% orientada a dados reais** — zero mocks. Toda a informação vem da API FastAPI em `GET /api/v1/reports/`.

#### Funções Principais

| Função | Responsabilidade |
|---|---|
| `fetchReportsList()` | `GET /api/v1/reports/` — carrega e popula a tabela ao montar a página |
| `receiveNewReportEvent(data)` | `POST /api/v1/reports/` — salva novo laudo e atualiza a tabela sem reload |
| `handleDelete(id)` | `DELETE /api/v1/reports/{id}` — remove laudo do storage e da tabela |
| `handleDownloadPDF(id)` | `GET /api/v1/reports/{id}/pdf` — gera e faz download do PDF via motor ReportLab |
| `handleGenerateNew()` | Abre modal para colar Hash do Commit + selecionar Modelo de Conformidade |

#### Componentes Visuais
- **KPI Cards:** Total de Laudos | Risco Crítico | Risco Alto | Aprovados — alimentados dinamicamente do array de estado
- **Filtros em tempo real:** Busca por texto (título, alvo, tipo) + dropdown de severidade (Crítico / Alto / Médio / Baixo / Seguro)
- **DataGrid de Laudos:** Colunas — Data, Alvo (Commit/Projeto), Tipo de Relatório, Risco (badge colorido), Ações (PDF + Excluir)
- **Modal de Geração Sob Demanda:** Formulário com campo de Hash e select de Modelo de Conformidade. Sem `alert()` genérico — toda falha é tratada com toast visual.

---

## Motor de PDF (`POST /api/v1/reports/generate-pdf`)

O backend expõe um **motor de geração de PDF stateless** e agnóstico, que pode ser chamado de qualquer ponto do sistema sem depender da interface gráfica.

### Como Funciona

1. **Payload de entrada:**
   ```json
   {
     "scan_data":        { "semgrep": {}, "trivy": {}, "gitleaks": [], "checkov": {} },
     "compliance_model": "TECNICO",
     "severity_filter":  "HIGH",
     "target_name":      "commit-a1b2c3d"
   }
   ```

2. **Filtragem por severidade:** O motor percorre todos os achados dos 4 scanners (Semgrep, Trivy, Gitleaks, Checkov), os normaliza em uma lista plana e descarta tudo que estiver abaixo do threshold solicitado.

3. **Inteligência do Modelo de Conformidade:**
   - **`TECNICO`** → Tabela com colunas: Severidade, Ferramenta, Arquivo, Regra/CWE, Detalhes. Ideal para equipes de AppSec/Dev.
   - **`ISO_27001`** → Tabela com colunas: Ferramenta, Controle/Regra, Arquivo, Não-Conformidade. Foco em controles do SGSI.
   - **`EXECUTIVO`** → Tabela com colunas: Severidade, Ferramenta, Descrição do Risco. Linguagem de negócio, sem termos técnicos profundos.

4. **Geração em memória:** ReportLab escreve o PDF em `io.BytesIO()`. **Nenhum arquivo é gravado em disco no servidor.**

5. **Retorno:** `StreamingResponse` com `Content-Disposition: attachment` e nome de arquivo dinâmico.

### Exemplo de uso direto (curl)
```bash
curl -X POST http://localhost:8000/api/v1/reports/generate-pdf \
  -H "Content-Type: application/json" \
  -d '{
    "scan_data":        {"semgrep": {"results": []}, "trivy": {}, "gitleaks": [], "checkov": {}},
    "compliance_model": "EXECUTIVO",
    "severity_filter":  "HIGH",
    "target_name":      "previswit-core"
  }' --output relatorio_executivo.pdf
```

---

## Referência de Endpoints da API — Relatórios

| Método | Rota | Descrição |
|---|---|---|
| `GET` | `/api/v1/reports/` | Lista todos os laudos persistidos (sem mocks) |
| `POST` | `/api/v1/reports/` | Recebe e persiste novo laudo + `scan_data` |
| `DELETE` | `/api/v1/reports/{id}` | Exclui laudo e arquivo de scan_data associado |
| `GET` | `/api/v1/reports/{id}` | Retorna metadados de um laudo específico |
| `POST` | `/api/v1/reports/generate-pdf` | **Motor de PDF stateless** (não persiste em disco) |
| `GET` | `/api/v1/reports/{id}/pdf` | Gera PDF de laudo já persistido com scan_data |
| `GET` | `/api/v1/reports/templates/list` | Lista modelos de conformidade disponíveis |

---

> *Este README.md serve como documento de Hand-Off técnico para novos desenvolvedores e auditores que forem trabalhar com os motores de Risco, PDF e Conformidade da plataforma PreviSwit AI-ASPM.*

---

## 👥 Integrantes

| Nome | RM |
|------|----|
| Bruno Tomé Duarte | RM 571712 |
| Matheus Pascoal Craveiro | RM 572715 |
| Gabriel Zobolli Carnevalli | RM 571728 |
| Heitor Fonseca Amorim dos Santos | RM 569118 |
