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
