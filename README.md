# PreviSwit ASPM - Dashboard Platform

Bem-vindo ao repositório do **PreviSwit ASPM** (Application Security Posture Management). 
Esta plataforma unifica o gerenciamento de vulnerabilidades, orquestração de scans de segurança e insights através de Inteligência Artificial.

## 🚀 Arquitetura (Clean Architecture)

A aplicação foi estruturada seguindo as melhores práticas de Clean Architecture e separação de módulos. 
Nós utilizamos uma abordagem **Single Page Application (SPA)** com:

- **Frontend:** React 18, Vite e Tailwind CSS.
- **Backend:** FastAPI (Python), responsável pelas integrações com bancos de dados e ferramentas de SecOps.
- **Roteamento SPA:** `react-router-dom` mapeando perfeitamente para os 8 módulos principais da API.
- **Servidor Web (Produção):** Nginx super leve através de um container Multi-stage build. 

### 📂 Módulos Principais
1. **Visão Geral:** Dashboard consolidado.
2. **Ativos & Produtos:** Inventário dinâmico.
3. **Engajamentos & Scans:** Orquestração de pipelines e WebSockets para acompanhamento de logs em tempo real.
4. **Central de Findings:** Triagem e deduplicação de vulnerabilidades.
5. **IA Insights:** Recomendações de segurança geradas por IA.
6. **Métricas de Risco:** Score evolutivo.
7. **Relatórios:** Exportações executivas e técnicas.
8. **Integrações / Configurações:** Gestão de usuários, RBAC e conexões (Jira, GitHub Actions, Nuclei, Trivy, etc).

---

## 🛠️ Como rodar o projeto localmente

A maneira mais fácil e recomendada de executar toda a plataforma é utilizando o Docker Compose, que constrói a API (Backend) e o App (Frontend) automaticamente e lida com todas as dependências.

### 1. Requisitos
- **Docker** e **Docker Compose** instalados na máquina.

### 2. Inicializando os containers
Abra o terminal na raiz do projeto (onde está o `docker-compose.yml`) e execute:

```bash
docker compose up -d --build
```

O Docker fará o processo de **Multi-stage build**:
1. Baixará o Node.js para compilar e empacotar o código React.
2. Transferirá os arquivos otimizados (`/dist`) para um servidor Nginx puramente estático.
3. Subirá o servidor FastAPI para a API.

*Nota: O `node_modules` é ignorado neste processo, garantindo imagens Docker minúsculas e de alta performance.*

### 3. Acessando a Aplicação
Após o término do build, você poderá acessar:
- **Frontend (Console):** [http://localhost:3000](http://localhost:3000)
  - *Login padrão:* Usuário `admin` / Senha `admin`
- **Backend (Swagger UI):** [http://localhost:10000/docs](http://localhost:10000/docs)

### 4. Parando os containers
Para interromper a execução, execute:
```bash
docker compose down
```

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

*Certifique-se de que a API (previswit-server) esteja rodando no Docker para que as chamadas no frontend não falhem.*
