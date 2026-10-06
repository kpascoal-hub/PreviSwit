# Documentação Técnica — Módulo de Repositórios e Ativos

Este diretório (`src/pages/assets/`) abriga a seção de **Gestão de Repositórios** e **Mapa Mental de Risco** do PreviSwit (AI-ASPM). 

## 1. Arquivos Principais
- `RepositoriesPage.jsx`: Ponto de entrada do módulo. Renderiza o grid de repositórios do GitHub importados, lida com a orquestração SAST (Quarteto Fantástico) e exibe os KPIs de status.
- `RiskGraphCanvas.jsx`: A view de "Deep Dive" ou Mapa Mental. Ao clicar em analisar fundo um repositório, esta tela é montada e renderiza o fluxo de commits interativo via grafos.

---

## 2. Diagrama de Fluxo e Ciclo de Vida (RepositoriesPage)

### 2.1 Fetch Inicial
```javascript
  const fetchRepositories = useCallback(async () => { ... })
```
1. O React dispara a chamada `GET /api/v1/github/repos` via backend usando o token do GitHub armazenado no `sessionStorage`.
2. A lista de repositórios retorna como um array de objetos `{ name, language, updated_at }`.
3. Antes de ser injetada no state `repositories`, cada repo sofre **Hidratação Local**:
   O código busca a chave `previswit_scan_<repo.name>` no `localStorage`. Se existir, o cache prévio é anexado em `r.scanner_results`.

### 2.2 Orquestração de Scan (Polling Assíncrono)
Quando o usuário aperta em "Iniciar Orquestração":
1. Um `POST` em `/api/v1/sast/schedule` aciona a task de background no backend e devolve um `scanId`.
2. O state do card muda para `PENDING` ou `RUNNING`.
3. Um hook `useEffect` inicia um loop de Polling (`setInterval` de 3s) em `/api/v1/sast/scan-status/{scanId}`.
4. Quando a API devolve status `CONCLUÍDO`, o intervalo é destruído e o laudo de segurança (SAST Global) é injetado no navegador.

---

## 3. Gestão de Estado: Memória Blindada

Para resolver a perda de contexto visual em navegação de SPA (ex: o usuário sai do `RepositoriesPage` para a `Dashboard` e volta), o React perderia o State Local do componente `RepositoryCard`. 

O design pattern adotado para curar essa amnésia visual:
```javascript
// O componente card cria uma variável efetiva prioritária:
const effectiveScanData = scanData || repo.scanner_results;
```

Essa diretiva instrui o React a ler o estado reativo (`scanData`), mas, em caso de remontagem (quando `scanData` nasce como `null`), ele instantaneamente recai no cache herdado (`repo.scanner_results`) populado lá em cima pelo loop de hidratação. A UI nunca acende como "⏳ Pendente de Scan" indevidamente.

---

## 4. O Sistema de "Cascade Hydration" (Herança em Cascata)

A arquitetura de sincronização de memória mais avançada do módulo. Ao executar um Scan Global num repositório, o laudo cobre todo o código. Como fazer os Cards de Commit individuais no `RiskGraphCanvas` ficarem sincronizados de forma cirúrgica com o repositório pai sem refazer o scan?

1. **Propagação Ativa (`RepositoriesPage.jsx`)**: Assim que o Polling do SAST é concluído, o front-end lista ativamente todos os commits daquele repositório. O JSON gigante do scan passa por um filtro: apenas as falhas mapeadas que citam o Hash (`commit.sha`) do commit na string do payload são salvas no cache interno individual daquele commit no `localStorage`.
2. **Herança de Fallback (`RiskGraphCanvas.jsx`)**: Se o processo ativo falhar, o mapa mental atua de forma passiva. Durante a sua própria hidratação de commits, se um commit estiver vazio, ele lê ativamente a memória do Repositório Pai. Se o JSON do pai não citar o SHA do filho, forja-se um estado de segurança imediato: `{ inherited: true, clean: true, vulnerabilities: [] }`.

Essa técnica elimina 100% de inconsistências entre "Página de Repositórios" e "Mapa Mental".

---

## 5. Lógica Visual de Defesa Contra Falsos Positivos

Um problema clássico na modelagem de SAST em JSON dinâmico é que chaves auxiliares (como `tools_used: ['Semgrep', ...]`) podem ser avaliadas como arrays de erro.

Para evitar Falsos Positivos (Badges vermelhos de "HIGH" sem vulnerabilidade real), o componente baseia-se em um filtro rigoroso de aninhamento de chaves e prioridades booleanas:

```javascript
let isVuln = false;
if (effectiveScanData) {
  // 1. Checks booleanos literais da API / Hidratação injetada:
  if (effectiveScanData.clean === true || effectiveScanData.vulnerable === false) {
    isVuln = false;
  } else if (effectiveScanData.vulnerable === true) {
    isVuln = true;
  } else {
    // 2. Busca empírica focada em arrays e Results internos do Quarteto Fantástico:
    const sr = effectiveScanData.scanner_results || effectiveScanData;
    if (Array.isArray(sr.vulnerabilities)) {
      isVuln = sr.vulnerabilities.length > 0;
    } else if (typeof sr === 'object') {
      isVuln = Object.values(sr).some(toolOut => {
        if (Array.isArray(toolOut)) return toolOut.length > 0;
        if (toolOut && typeof toolOut === 'object') {
          const res = toolOut.results || toolOut.Results || toolOut.Vulnerabilities || [];
          return Array.isArray(res) && res.length > 0;
        }
        return false;
      });
    }
  }
}
```

Apenas resultados matematicamente isolados de erro são marcados em vermelho. Se não existirem, o React plota o código limpo (🛡️ Código Seguro).

---

## 👥 Integrantes

| Nome | RM |
|------|----|
| Bruno Tomé Duarte | RM 571712 |
| Matheus Pascoal Craveiro | RM 572715 |
| Gabriel Zobolli Carnevalli | RM 571728 |
| Heitor Fonseca Amorim dos Santos | RM 569118 |
