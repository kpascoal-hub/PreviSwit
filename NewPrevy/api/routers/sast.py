"""
PreviSwit AI-ASPM — Router: SAST Dispatch
Orquestrador HTTP→WebSocket para as ferramentas SAST individuais embarcadas no Agente.

Fluxo:
  Frontend → POST /api/v1/sast/scan
           → FastAPI (aqui) → manager.send_to_agent() via WebSocket
           → Agent (ws_listener) → run_semgrep | run_gitleaks | run_checkov
           → resultado retorna via WebSocket → Dashboard

Endpoints:
  POST /api/v1/sast/scan          — Dispara uma ferramenta SAST no agente
  GET  /api/v1/sast/tools         — Lista ferramentas disponíveis e status do agente
  GET  /api/v1/sast/status/{agent} — Verifica se o agente está conectado
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Literal
from datetime import datetime, timezone
import logging

logger = logging.getLogger("previswit.sast")

router = APIRouter(prefix="/sast", tags=["SAST Dispatch (Agent)"])


# ─── Tipos aceitos ────────────────────────────────────────────────────────────
SASTAction = Literal["RUN_SEMGREP", "RUN_GITLEAKS", "RUN_CHECKOV"]

TOOL_META = {
    "RUN_SEMGREP": {
        "name": "Semgrep",
        "description": "SAST genérico multi-linguagem via análise de AST.",
        "category": "SAST",
        "supported_languages": ["Python", "JS", "Go", "Java", "Ruby", "PHP", "C/C++", "e mais"],
    },
    "RUN_GITLEAKS": {
        "name": "Gitleaks",
        "description": "Detecção de segredos, tokens e credenciais em código-fonte.",
        "category": "Secrets Detection",
        "supported_languages": ["Todos (análise de texto)"],
    },
    "RUN_CHECKOV": {
        "name": "Checkov",
        "description": "Análise estática de IaC: Terraform, Kubernetes, Dockerfile, ARM, Bicep.",
        "category": "IaC Security",
        "supported_languages": ["Terraform", "Kubernetes", "Dockerfile", "ARM", "CloudFormation"],
    },
}


class SASTScanRequest(BaseModel):
    action: SASTAction                     # "RUN_SEMGREP" | "RUN_GITLEAKS" | "RUN_CHECKOV"
    target: str                            # Caminho absoluto no container do Agente (ex: /app/repo)
    agent_id: Optional[str] = "agent_01"  # ID do agente alvo (padrão: agent_01)


# ─── Referência lazy ao manager do api.py ────────────────────────────────────
# O import é feito de forma lazy para evitar circular imports, já que o
# manager é instanciado no módulo api.py (o entry-point da aplicação).
def _get_manager():
    """Obtém o ConnectionManager instanciado em api.py."""
    import api.api as _api_module
    return _api_module.manager


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.post(
    "/scan",
    summary="Disparar scan SAST individual no Agente",
    description=(
        "Envia um comando de scan para o Agente conectado via WebSocket.\n\n"
        "O resultado é retornado de forma assíncrona pelo WebSocket do Dashboard (`/ws/web_dashboard`).\n\n"
        "**Ações disponíveis:** `RUN_SEMGREP`, `RUN_GITLEAKS`, `RUN_CHECKOV`"
    ),
)
async def dispatch_sast_scan(body: SASTScanRequest):
    """
    Despacha um comando SAST para o Agente via WebSocket.
    O Agente executa o scan e retorna o resultado pelo túnel WebSocket do Dashboard.
    """
    if not body.target.strip():
        raise HTTPException(status_code=400, detail="Campo 'target' não pode estar vazio.")

    manager = _get_manager()

    # Verifica se o agente está conectado
    if body.agent_id not in manager.agent_ws:
        raise HTTPException(
            status_code=503,
            detail=(
                f"Agente '{body.agent_id}' não está conectado ao servidor. "
                "Verifique se o container do Agente está rodando e conectado via WebSocket."
            ),
        )

    # Monta o comando no protocolo esperado pelo ws_listener.py do Agente
    command = {
        "action": body.action,
        "target": body.target,
        "requested_at": datetime.now(timezone.utc).isoformat(),
    }

    await manager.send_to_agent(body.agent_id, command)

    tool_info = TOOL_META.get(body.action, {})

    return {
        "status": "dispatched",
        "message": f"Comando '{body.action}' enviado para o agente '{body.agent_id}'.",
        "agent_id": body.agent_id,
        "action": body.action,
        "tool": tool_info.get("name", body.action),
        "target": body.target,
        "note": "O resultado chegará de forma assíncrona pelo WebSocket do Dashboard (/ws/web_dashboard).",
        "dispatched_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get(
    "/tools",
    summary="Listar ferramentas SAST disponíveis",
)
def list_sast_tools():
    """Retorna os metadados das ferramentas SAST disponíveis no Agente."""
    return {
        "tools": [
            {"action": action, **meta}
            for action, meta in TOOL_META.items()
        ]
    }


@router.get(
    "/status/{agent_id}",
    summary="Verificar status de conexão de um Agente",
)
def agent_status(agent_id: str):
    """Verifica se um Agente específico está conectado ao servidor via WebSocket."""
    manager = _get_manager()
    connected = agent_id in manager.agent_ws
    return {
        "agent_id": agent_id,
        "connected": connected,
        "status": "online" if connected else "offline",
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get(
    "/agents",
    summary="Listar todos os Agentes conectados",
)
def list_connected_agents():
    """Retorna a lista de todos os Agentes atualmente conectados ao servidor."""
    manager = _get_manager()
    agents = list(manager.agent_ws.keys())
    return {
        "connected_agents": agents,
        "count": len(agents),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


# ─── Endpoint: Análise de Commit Individual (SAST + AI) ──────────────────────

class CommitAnalyzeRequest(BaseModel):
    sha:     str                          # Hash completo do commit
    message: Optional[str] = ""          # Mensagem do commit
    author:  Optional[str] = ""          # Autor do commit
    date:    Optional[str] = ""          # Data do commit (ISO 8601)
    branch:  Optional[str] = ""          # Branch de origem
    files:   Optional[list] = []         # Lista de arquivos alterados (patch diff)
    repo_url: Optional[str] = ""         # URL do repositório para clonagem
    gemini_key: Optional[str] = None     # Chave Gemini BYOK (alternativa ao Header)

from fastapi import Header as FastAPIHeader
import subprocess
import os
import shutil
import tempfile
import json

@router.post(
    "/analyze-commit",
    summary="Análise SAST + AI de um commit individual",
    description=(
        "Recebe os dados de um commit e realiza varredura com Trivy executado via subprocess "
        "num clone efêmero do repositório."
    ),
)
async def analyze_commit(
    body: CommitAnalyzeRequest,
    x_gemini_key: Optional[str] = FastAPIHeader(default=None, alias="X-Gemini-Key"),
):
    """
    Execução de SAST Real (Trivy) via Gêmeo Efêmero
    """
    if not body.repo_url:
        logger.warning(f"repo_url não fornecido para {body.sha}. Apenas arquivos patchados serão ignorados pelo Trivy.")
        # Sem repo_url, não podemos clonar
        # Caso precise falhar: raise HTTPException(status_code=400, detail="repo_url é obrigatório")

    all_findings = []
    diretorio_temporario = tempfile.mkdtemp(prefix="previswit_sast_")

    try:
        if body.repo_url:
            # 1. Clonagem Cirúrgica
            subprocess.run(["git", "clone", body.repo_url, diretorio_temporario], capture_output=True, check=False)
            subprocess.run(["git", "checkout", body.sha], cwd=diretorio_temporario, capture_output=True, check=False)

            # 2. A Execução Real (O Quarteto Fantástico)
            
            # Semgrep
            semgrep_res = subprocess.run(["semgrep", "scan", "--config", "auto", "--json", diretorio_temporario], capture_output=True, text=True)
            try:
                semgrep_data = json.loads(semgrep_res.stdout) if semgrep_res.stdout else {}
            except Exception:
                semgrep_data = {}
                
            # Trivy
            trivy_res = subprocess.run(["trivy", "fs", "--format", "json", diretorio_temporario], capture_output=True, text=True)
            try:
                out_text = trivy_res.stdout
                if "{" in out_text:
                    out_text = out_text[out_text.index("{"):]
                trivy_data = json.loads(out_text) if out_text else {}
            except Exception:
                trivy_data = {}
                
            # Gitleaks
            gitleaks_res = subprocess.run(["gitleaks", "detect", "--source", diretorio_temporario, "--report-format", "json", "--no-git", "--exit-code", "0"], capture_output=True, text=True)
            try:
                gitleaks_data = json.loads(gitleaks_res.stdout) if gitleaks_res.stdout else []
            except Exception:
                gitleaks_data = []
                
            # Checkov
            checkov_res = subprocess.run(["checkov", "-d", diretorio_temporario, "-o", "json", "--soft-fail"], capture_output=True, text=True)
            try:
                out_checkov = checkov_res.stdout
                if "{" in out_checkov or "[" in out_checkov:
                    first_brace = out_checkov.find("{")
                    first_bracket = out_checkov.find("[")
                    if first_brace != -1 and first_bracket != -1:
                        start_idx = min(first_brace, first_bracket)
                    else:
                        start_idx = max(first_brace, first_bracket)
                    out_checkov = out_checkov[start_idx:]
                checkov_data = json.loads(out_checkov) if out_checkov else {}
            except Exception:
                checkov_data = {}

            # 3. Unificação e Retorno
            semgrep_vuln = bool(semgrep_data.get("results", []))
            trivy_vuln = False
            for r in trivy_data.get("Results", []):
                if r.get("Vulnerabilities") or r.get("Misconfigurations"):
                    trivy_vuln = True
                    break
            gitleaks_vuln = bool(gitleaks_data)
            checkov_vuln = False
            if isinstance(checkov_data, list):
                for report in checkov_data:
                    if report.get("results", {}).get("failed_checks"):
                        checkov_vuln = True
                        break
            elif isinstance(checkov_data, dict):
                if checkov_data.get("results", {}).get("failed_checks"):
                    checkov_vuln = True
                    
            is_vulnerable = semgrep_vuln or trivy_vuln or gitleaks_vuln or checkov_vuln
            
            scanner_results = {
                "semgrep": semgrep_data,
                "trivy": trivy_data,
                "gitleaks": gitleaks_data,
                "checkov": checkov_data
            }

    finally:
        # 4. Limpeza Letal (Crucial)
        shutil.rmtree(diretorio_temporario, ignore_errors=True)

    severity = "HIGH" if is_vulnerable else "CLEAN"

    return {
        "sha":         body.sha,
        "vulnerable":  is_vulnerable,
        "severity":    severity,
        "scanner_results": scanner_results,
        "tools_used":  ["Semgrep", "Trivy", "Gitleaks", "Checkov"],
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
    }

