"""
API REST — PreviSwit v3
Expõe os resultados via FastAPI para integração com outros sistemas.
"""
import json, os, glob
from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel
from typing import Dict
from config import Config

app = FastAPI(
    title="PreviSwit API",
    description="AI-Powered Pentest Framework — PreviSwit",
    version="3.0"
)


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
            if data.get("action") == "START_SCAN":
                # Encaminha o pedido de scan para o agente_01
                await manager.send_to_agent("agent_01", data)
                await manager.send_to_dashboard({"action": "LOG", "message": "🚀 Comando enviado para o Agente_01"})
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
                # Tudo que o agente falar, a gente repassa pro Dashboard
                await manager.send_to_dashboard(data)
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        manager.disconnect_agent(agent_id)
