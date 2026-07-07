"""
API REST — PreviSwit AI-ASPM v5
Expõe todos os domínios ASPM via FastAPI: Assets, Engagements, Findings,
AI Insights, AI Chat Copilot (Gemini), Risk Metrics, Reports,
GitHub Integration, ASPM Parsers (SAST/Secrets/IaC), Integrations e Settings.
"""
import json, os, glob
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict

# ─── Routers ─────────────────────────────────────────────────────────────────
from api.routers.auth         import router as auth_router
from api.routers.assets       import router as assets_router
from api.routers.engagements  import router as engagements_router
from api.routers.findings     import router as findings_router
from api.routers.ai_insights  import router as ai_router
from api.routers.ai_chat      import router as ai_chat_router   # ← Novo Cerebro Central
from api.routers.risk         import router as risk_router
from api.routers.reports      import router as reports_router
from api.routers.integrations import router as integrations_router
from api.routers.github import router as github_router
from api.routers.aspm_parsers import router as aspm_parsers_router
from api.routers.settings     import router as settings_router
from api.routers.sast         import router as sast_router          # ← SAST Dispatch (Agente)
from api.routers.cloud        import router as cloud_router         # ← Cloud Security & IaC (CSPM)
from api.routers.containers   import router as containers_router    # ← Container Security (Trivy Image)
from config import Config

app = FastAPI(
    title="PreviSwit AI-ASPM API",
    description=(
        "## PreviSwit — AI-Powered Application Security Posture Management\n\n"
        "Plataforma ASPM de elite com os seguintes módulos:\n\n"
        "### 📦 Gestão de Ativos\n"
        "- **Assets & Products**: Inventário completo de ativos digitais\n"
        "- **Engagements & Scans**: Histórico e orquestração de scans\n"
        "- **Findings & Triage**: Central de triagem com deduplication por IA\n\n"
        "### 🤖 Inteligência Artificial (Gemini)\n"
        "- **AI Insights**: Remediação guiada, Threat Intelligence e Risk Analysis\n"
        "- **AI Chat Copilot**: Chat conversacional com memória persistente por sessão/repositório\n\n"
        "### 🕵️ Segurança & Análise\n"
        "- **ASPM Parsers**: Ingestão e normalização de resultados SAST, Secrets e IaC\n"
        "- **Risk Metrics**: Score evolutivo de risco e compliance\n\n"
        "### 🔗 Integrações\n"
        "- **GitHub Integration**: Commits, branches, diffs e análise de repositórios via BYOT\n"
        "- **Integrations**: CI/CD, Jira, Slack e conectores externos\n\n"
        "### ⚙️ Plataforma\n"
        "- **Reports**: Relatórios executivos e técnicos (PDF/HTML)\n"
        "- **Settings**: Usuários, RBAC e auditoria\n"
    ),
    version="5.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ─── CORS ────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Registrar Routers ───────────────────────────────────────────────────────
app.include_router(auth_router)
app.include_router(assets_router,       prefix="/api/v1", tags=["Assets & Products"])
app.include_router(engagements_router,  prefix="/api/v1", tags=["Engagements & Scans"])
app.include_router(findings_router,     prefix="/api/v1", tags=["Findings & Triage"])
app.include_router(ai_router,           prefix="/api/v1", tags=["AI & Insights"])
app.include_router(ai_chat_router,      prefix="/api/v1", tags=["AI Chat (Copilot)"])
app.include_router(risk_router,         prefix="/api/v1", tags=["Risk & Posture"])
app.include_router(reports_router,      prefix="/api/v1", tags=["Reports"])
app.include_router(integrations_router, prefix="/api/v1", tags=["Integrations"])
app.include_router(aspm_parsers_router, prefix="/api/v1", tags=["ASPM Parsers (SAST/Secrets/IaC)"])
app.include_router(github_router,       prefix="/api/v1", tags=["GitHub"])
app.include_router(settings_router,     prefix="/api/v1", tags=["Settings & Users"])
app.include_router(sast_router,         prefix="/api/v1", tags=["SAST Dispatch (Agent)"])
app.include_router(cloud_router,        prefix="/api/v1", tags=["Cloud Security & IaC (CSPM)"])
app.include_router(containers_router,   prefix="/api/v1", tags=["Container Security (Trivy Image)"])


class ScanRequest(BaseModel):
    target:     str
    pipeline:   str = "all"
    shodan_key: str = ""
    vt_key:     str = ""


# ─── Gerenciador de WebSockets ──────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.dashboard_ws = None
        self.agent_ws: Dict[str, WebSocket] = {}

    async def connect_dashboard(self, websocket: WebSocket):
        await websocket.accept()
        self.dashboard_ws = websocket

    async def connect_agent(self, websocket: WebSocket, agent_id: str):
        await websocket.accept()
        self.agent_ws[agent_id] = websocket

    def disconnect_dashboard(self):
        self.dashboard_ws = None

    def disconnect_agent(self, agent_id: str):
        if agent_id in self.agent_ws:
            del self.agent_ws[agent_id]

    async def send_to_dashboard(self, message: dict):
        if self.dashboard_ws:
            try:
                await self.dashboard_ws.send_json(message)
            except:
                pass

    async def send_to_agent(self, agent_id: str, message: dict):
        if agent_id in self.agent_ws:
            try:
                await self.agent_ws[agent_id].send_json(message)
            except:
                pass

manager = ConnectionManager()

# ─── Cache global de capabilities reportadas pelo agente ───────────────────────
# Atualizado toda vez que o agente conecta e envia AGENT_CAPABILITIES.
# Thread-safe para leitura (GIL Python garante atomicidade de atribuicões de dict).
_agent_capabilities: dict = {}


@app.get("/", response_class=HTMLResponse)
def root():
    path = os.path.join(os.path.dirname(__file__), "..", "templates", "login.html")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    path = os.path.join(os.path.dirname(__file__), "..", "templates", "dashboard.html")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


@app.get("/reports")
def list_reports():
    files = glob.glob(f"{Config.REPORT_DIR}/*.json")
    return {"reports": [os.path.basename(f) for f in files]}


@app.get("/reports/{filename}")
def get_report(filename: str):
    path = os.path.join(Config.REPORT_DIR, filename)
    if not os.path.exists(path):
        raise HTTPException(404, "Relatório não encontrado.")
    with open(path) as f:
        return json.load(f)


@app.get("/dashboard/{filename}", response_class=HTMLResponse)
def get_dashboard(filename: str):
    path = os.path.join(Config.REPORT_DIR, filename)
    if not os.path.exists(path):
        raise HTTPException(404, "Dashboard não encontrado.")
    with open(path, encoding="utf-8") as f:
        return f.read()


@app.get("/ai-memory")
def ai_memory():
    if not os.path.exists(Config.AI_MEMORY):
        return {}
    with open(Config.AI_MEMORY) as f:
        return json.load(f)


@app.post("/scan")
def start_scan(req: ScanRequest, bg: BackgroundTasks):
    def _run():
        import subprocess
        cmd = ["python", "main.py", req.target, "--pipeline", req.pipeline]
        if req.shodan_key:
            cmd += ["--shodan", req.shodan_key]
        if req.vt_key:
            cmd += ["--vt", req.vt_key]
        subprocess.run(cmd)
    bg.add_task(_run)
    return {"status": "started", "target": req.target, "pipeline": req.pipeline}


# ─── WebSockets Endpoints ───────────────────────────────────────────────────

@app.websocket("/ws/web_dashboard")
async def websocket_dashboard(websocket: WebSocket):
    await manager.connect_dashboard(websocket)
    try:
        while True:
            data = await websocket.receive_json()
            action = data.get("action")

            # Ações que devem ser encaminhadas diretamente ao agente
            _AGENT_ACTIONS = {
                "START_SCAN",
                "RUN_SEMGREP",
                "RUN_GITLEAKS",
                "RUN_CHECKOV",
            }

            if action in _AGENT_ACTIONS:
                agent_id = data.get("agent_id", "agent_01")
                await manager.send_to_agent(agent_id, data)
                await manager.send_to_dashboard({
                    "action": "LOG",
                    "message": f"🚀 Comando '{action}' enviado para '{agent_id}'",
                })
    except WebSocketDisconnect:
        manager.disconnect_dashboard()


@app.websocket("/ws/{agent_id}")
async def websocket_agent(websocket: WebSocket, agent_id: str):
    await manager.connect_agent(websocket, agent_id)
    try:
        while True:
            data_str = await websocket.receive_text()
            try:
                data = json.loads(data_str)

                # ── Captura AGENT_CAPABILITIES e atualiza o cache global ────────
                if data.get("action") == "AGENT_CAPABILITIES":
                    global _agent_capabilities
                    _agent_capabilities = {
                        **data.get("data", {}),
                        "_received_at": datetime.now(timezone.utc).isoformat(),
                        "_agent_id":    agent_id,
                    }
                    import logging
                    logging.getLogger("api").info(
                        "✅ AGENT_CAPABILITIES recebido de '%s' — %s ferramentas, %s APIs",
                        agent_id,
                        len(_agent_capabilities.get("pentest_tools", [])),
                        len(_agent_capabilities.get("api_integrations", [])),
                    )

                # Tudo que o agente falar, repassa pro Dashboard
                await manager.send_to_dashboard(data)
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        manager.disconnect_agent(agent_id)
