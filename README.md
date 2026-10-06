# PreviSwit ASPM - Dashboard Platform.

Bem-vindo ao repositório do **PreviSwit ASPM** (Application Security Posture Management). 
Esta plataforma unifica o gerenciamento de vulnerabilidades, orquestração de scans de segurança e insights através de Inteligência Artificial.

## 🚀 Arquitetura

A plataforma roda em **3 containers Docker** numa rede isolada (`previswit-net`):

| Container | Função | Porta no host |
|-----------|--------|---------------|
| `previswit-frontend` | Dashboard React 18 + Vite + Tailwind, servido por Nginx (proxy reverso para a API) | **3000** |
| `previswit-server` | API FastAPI (Python) + Hub WebSocket que orquestra os scans | **10100** |
| `previswit-agent` | Agente de pentest em Kali Linux (Nmap, Gobuster, Nuclei, Trivy, Gitleaks) que recebe ordens do server via WebSocket | — (interno) |

A IA (Google Gemini) é usada para triagem de findings, resumos de scans, Copilot e recomendações de risco.

### 📂 Módulos Principais
1. **Visão Geral:** dashboard consolidado da postura de segurança.
2. **Ativos:** inventário por tipo — Repositórios (GitHub/GitLab), Cloud (AWS/Azure/GCP), Contêineres (imagens Docker), Máquinas Virtuais e Domínios & APIs.
3. **Pentest:** orquestração de pentests com logs em tempo real via WebSocket.
4. **Central de Findings:** triagem e deduplicação de vulnerabilidades.
5. **IA Insights:** recomendações e Copilot de segurança com IA.
6. **Métricas de Risco:** Radar de risco, Compliance por framework, Plano de Ação e Simulador de investimento.
7. **Relatórios:** exportações executivas e técnicas em PDF.
8. **Integrações / Configurações:** chaves de API, usuários e conexões externas.

---

## 🛠️ Instalação em uma máquina nova (passo a passo)

### 1. Pré-requisitos

| Item | Observação |
|------|------------|
| **Docker** + **Docker Compose v2** | Windows/macOS: [Docker Desktop](https://www.docker.com/products/docker-desktop/). Linux: Docker Engine + plugin `docker compose`. |
| **Git** | Para clonar o repositório. |
| **Hardware** | Recomendado: 8 GB de RAM e ~15 GB livres em disco (a imagem do agente é baseada em Kali Linux). |
| **Internet** | Necessária no build (download de imagens e ferramentas) e para a IA. |
| **Chave da API Gemini** *(opcional)* | Gratuita em [Google AI Studio](https://aistudio.google.com/app/apikey). Sem ela a plataforma funciona, mas os recursos de IA ficam desativados. |
| **GitHub Personal Access Token** *(opcional)* | Necessário apenas para listar e escanear repositórios **privados**. |

Confira se o Docker está funcionando:

```bash
docker --version
docker compose version
```

### 2. Clonar o repositório

```bash
git clone https://github.com/kpascoal-hub/PreviSwit.git
cd PreviSwit
```

### 3. Criar o arquivo `.env`

Na raiz do projeto (mesma pasta do `docker-compose.yml`), crie um arquivo chamado `.env` com o conteúdo abaixo. Todas as variáveis têm valor padrão, então o arquivo pode ficar mínimo:

```env
# IA — chave do Google Gemini (opcional; também pode ser informada pela interface)
GEMINI_API_KEY=

# Segurança — troque por um valor aleatório e longo
SECRET_KEY=troque-por-um-valor-aleatorio
TOKEN_EXPIRE_MINUTES=60
APP_ENV=production

# Recuperação de senha por e-mail (opcional)
SITE_URL=http://localhost:3000
SITE_NAME=PreviSwit ASPM
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
EMAIL_FROM=
```

> ⚠️ O `.env` contém segredos e está no `.gitignore` — **nunca** faça commit dele.

### 4. Construir e subir os containers

```bash
docker compose up -d --build
```

O primeiro build leva alguns minutos (o agente baixa o Kali Linux e instala Nuclei, Trivy e Gitleaks). O Compose:
1. Compila o React e copia o resultado para um Nginx enxuto (multi-stage build);
2. Sobe a API FastAPI e aguarda o *healthcheck* ficar saudável;
3. Sobe o agente de pentest e o frontend, que dependem da API.

### 5. Verificar se está tudo no ar

```bash
docker compose ps
```

Os três serviços devem aparecer como `running`, e `previswit-server` e `previswit-frontend` como `(healthy)`. Para acompanhar os logs:

```bash
docker compose logs -f previswit-server
```

### 6. Acessar a aplicação

- **Console (Frontend):** [http://localhost:3000](http://localhost:3000)
- **API (Swagger UI):** [http://localhost:10100/docs](http://localhost:10100/docs)

**Login padrão:** usuário `admin` / senha `admin`.

---

## 🧭 Como usar a plataforma

Após o login, siga este fluxo para ver o ASPM funcionando de ponta a ponta:

1. **Configure a IA** — vá em **Integrações** → card *Google Gemini API (BYOK)*, cole sua chave e salve. A chave fica apenas na sessão do navegador e é enviada à API pelo header `X-Gemini-Key`.
2. **Cadastre e escaneie ativos** (menu **Ativos**):
   - **Repositórios:** informe seu GitHub Token quando solicitado, escolha um repositório e dispare o scan SAST/Secrets. O resultado aparece com resumo gerado por IA e histórico de scans.
   - **Cloud:** análise de postura de nuvem e IaC (CSPM).
   - **Contêineres:** scan de imagens Docker com Trivy.
   - **Domínios & APIs:** endpoints expostos na internet.
3. **Pentest** — execute pentests e acompanhe os logs em tempo real, transmitidos pelo agente via WebSocket.
4. **Central de Findings** — revise as vulnerabilidades consolidadas de todas as fontes, já deduplicadas, e faça a triagem.
5. **IA Insights** — converse com o Copilot e receba recomendações priorizadas sobre os findings.
6. **Métricas de Risco** — acompanhe a postura de segurança:
   - **Radar:** exposição por família de risco;
   - **Compliance:** aderência a frameworks de segurança;
   - **Plano de Ação:** correções priorizadas;
   - **Simulador:** impacto estimado de investimentos/correções no risco.
7. **Relatórios** — gere relatórios executivos e técnicos em PDF.
8. **Configurações** — gerencie usuários e preferências da plataforma.

---

## 🔧 Operação do dia a dia

| Ação | Comando |
|------|---------|
| Parar a plataforma | `docker compose down` |
| Subir novamente (sem rebuild) | `docker compose up -d` |
| Atualizar após `git pull` | `docker compose up -d --build` |
| Ver logs de um serviço | `docker compose logs -f <serviço>` |

Os dados da plataforma ficam em `NewPrevy/data/` (montado direto no container), portanto **não se perdem** ao recriar os containers. Os relatórios do agente ficam no volume Docker `agent_reports`.

## ❓ Solução de problemas

- **Erro ao publicar a porta da API no Windows** (`socket ... forbidden`): o Windows reserva a faixa 10136–11135. Por isso a API usa a porta **10100** no host; se ainda houver conflito, altere `"10100:10200"` no `docker-compose.yml`.
- **Porta 3000 ou 10100 já em uso:** pare o processo que usa a porta ou altere o mapeamento no `docker-compose.yml`.
- **Recursos de IA não respondem:** confira se a chave Gemini foi salva em **Integrações** (ou definida em `GEMINI_API_KEY` no `.env`).
- **Repositório privado não aparece / falha ao clonar:** informe um GitHub Personal Access Token com permissão de leitura (`repo`).
- **Scan de contêiner falha:** o Trivy precisa do socket do Docker (`/var/run/docker.sock`), já montado pelo Compose — verifique se o Docker Desktop/Engine está em execução.

---

## 🧑‍💻 Para Desenvolvedores (Modo Dev)

Se você precisa alterar componentes do React em tempo real (Hot Module Replacement) sem passar pelo Docker:

1. Entre na pasta do frontend:
   ```bash
   cd previswit-frontend
   ```
2. Instale as dependências:
   ```bash
   npm install
   ```
3. Inicie o servidor Vite:
   ```bash
   npm run dev
   ```

*O Vite usa a porta 3000 — pare o container `previswit-frontend` antes (`docker compose stop previswit-frontend`) e mantenha a API (`previswit-server`) rodando no Docker para que as chamadas do frontend não falhem.*


---

## 👥 Integrantes

| Nome | RM |
|------|----|
| Bruno Tomé Duarte | RM 571712 |
| Matheus Pascoal Craveiro | RM 572715 |
| Gabriel Zobolli Carnevalli | RM 571728 |
| Heitor Fonseca Amorim dos Santos | RM 569118 |

---

## 📄 Licença

Este projeto é licenciado sob a **GNU General Public License v3.0 ou posterior (GPL-3.0-or-later)**.
O texto completo está em [LICENSE.md](LICENSE.md) e cada arquivo de código-fonte contém o aviso de licença correspondente.
