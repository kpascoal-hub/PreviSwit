# PreviSwit Frontend Architecture

Bem-vindo à pasta `src` do frontend da PreviSwit (AI-ASPM).

Nesta pasta ficam contidos os componentes e lógicas que estruturam nossa SPA em Vanilla JS + Tailwind. O destaque desta camada é a nossa arquitetura de **Risk Graph (Grafo de Risco/Canvas Infinito)** localizada em `pages/assets/RiskGraphCanvas.jsx`.

## Risk Graph (Infinite Canvas)
O Risk Graph é uma representação visual avançada, projetada no estilo "Mapa Mental", que mapeia a árvore da vida dos Commits e Pull Requests de um repositório GitHub sem depender de pesadas bibliotecas gráficas externas.

### Core Features
- **Design Cyber Dark:** Utilizamos estilos minimalistas baseados em Tailwind, focado numa temática "hacker/corporativa" (`bg-[#060b13]`).
- **Bring Your Own Token (BYOT):** Toda a requisição para a API (que repassa para o GitHub) utiliza o `X-GitHub-Token` salvo na sessão, garantindo escalabilidade e segurança.
- **Navegação de Câmera:** Pan & Zoom integrados e fluidos através do mouse (inspirados em Figma/Miro).
- **Drag & Drop Isolado:** Todos os "Cards" no canvas podem ser reposicionados livremente pelo usuário. O motor calcula os vetores de movimento com base na escala de zoom atual.
- **SVG Dinâmicos:** As conexões entre "Nós Pai" e "Filhos" são desenhadas globalmente através de `<svg>` sobreposto no fundo. Elas reagem instantaneamente (graças à reatividade do React) ao deslocamento de qualquer card.

### As Ferramentas de Auditoria
- **Filtros Retráteis:** Há um menu de funil no canto superior do mapa onde se pode isolar Autores, determinar a Data Inicial e reverter a Linha do Tempo. Ele usa um sistema seguro de *Draft/Active States*, onde o filtro só aplica reações em cadeia no Virtual DOM ao apertar "Salvar".
- **Deep Dive Modal (Revisão de Código):** O usuário pode inspecionar o Diff/Patch do código nativamente na aplicação clicando em "Ver mais detalhes" no rodapé de um commit. Um Split-Pane carrega um explorador de arquivos e um terminal de sintaxe na própria tela, preservando 100% da posição de zoom/pan que ficou no fundo.
- **Micro-interações:** Barras de scroll foram redesenhadas globalmente (`index.css`) com perfil *Dark* e puxador branco em todas as áreas internas dos cards e modais, prevenindo perda de imersão.

---

> *Este README.md serve como documento de Hand-Off técnico para novos desenvolvedores que farão a manutenção dos motores de Pan, Zoom e SVG do RiskGraph.*
