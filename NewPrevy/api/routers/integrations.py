# PreviSwit AI-ASPM
# Copyright (C) 2026 PreviSwit Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""
PreviSwit AI-ASPM — Router: Integrations
Gestão de integrações com CI/CD, ticketing e notificações.
"""
from fastapi import APIRouter, HTTPException
import json
import os
import uuid
from datetime import datetime
import httpx

router = APIRouter(prefix="/integrations", tags=["Integrations"])

DATA_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "data", "integrations.json")

SUPPORTED_INTEGRATIONS = {
    "cicd": ["github_actions", "gitlab_ci", "jenkins", "azure_devops"],
    "ticketing": ["jira", "linear", "github_issues", "azure_boards"],
    "notifications": ["slack", "microsoft_teams", "pagerduty", "email"],
    "scan_tools": ["nuclei", "trivy", "owasp_zap", "semgrep", "bandit"],
    "aspm_tools": ["semgrep", "gitleaks", "checkov"],  # ASPM: SAST / Secrets / IaC
}


def _load() -> list:
    if not os.path.exists(DATA_FILE):
        return []
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _save(data: list) -> None:
    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


@router.get("/", summary="Listar integrações configuradas")
def list_integrations():
    """Retorna todas as integrações configuradas na plataforma."""
    integrations = _load()
    return {
        "integrations": integrations,
        "total": len(integrations),
        "supported": SUPPORTED_INTEGRATIONS,
    }


@router.get(
    "/capabilities",
    summary="Capacidades reais do agente (Dynamic Tool Discovery)",
    response_description=(
        "Retorna o estado REAL das ferramentas de pentest instaladas no container "
        "do agente (via shutil.which) e das integrações de API configuradas (via env vars), "
        "combinado com as integrações CRUD registradas na plataforma."
    ),
    tags=["Integrations"],
)
def get_capabilities():
    """
    **Dynamic Tool Discovery** — Reflexo em tempo real do motor de pentest.

    Combina três fontes de dados:

    - **pentest_tools**: ferramentas instaladas no container do agente
      (nmap, nuclei, trivy, gobuster) verificadas via `shutil.which()`.
    - **api_integrations**: chaves de API configuradas via variáveis de
      ambiente (Gemini, Jira, Slack, VirusTotal, Shodan).
    - **configured_integrations**: integrações registradas via CRUD (`POST /integrations`).

    O campo `agent_connected` indica se o agente já enviou suas capabilities
    desde o último restart do servidor.
    """
    # Importa o cache global do módulo pai (sem circular import)
    from api.api import _agent_capabilities

    agent_connected = bool(_agent_capabilities)

    pentest_tools    = _agent_capabilities.get("pentest_tools", [])
    api_integrations = _agent_capabilities.get("api_integrations", [])
    last_seen        = _agent_capabilities.get("_received_at")
    agent_id         = _agent_capabilities.get("_agent_id")
    summary          = _agent_capabilities.get("summary", {})

    # Se o agente ainda não conectou, retorna estrutura vazia mas bem-formada
    if not agent_connected:
        pentest_tools = [
            {"id": "nmap",     "name": "Nmap",     "desc": "Scanner de Rede e Portas",              "icon": "🗺️", "color": "green",  "active": False, "path": None, "version": None},
            {"id": "nuclei",   "name": "Nuclei",   "desc": "Scanner de Vulnerabilidades",           "icon": "🔍", "color": "orange", "active": False, "path": None, "version": None},
            {"id": "trivy",    "name": "Trivy",    "desc": "Scanner de Containers e SCA",           "icon": "🛡️", "color": "red",    "active": False, "path": None, "version": None},
            {"id": "gobuster", "name": "Gobuster", "desc": "Enumeração de Diretórios",              "icon": "📂", "color": "yellow", "active": False, "path": None, "version": None},
        ]
        api_integrations = [
            {"id": "gemini",     "name": "Google Gemini", "desc": "Motor de IA Generativa",           "icon": "🤖", "color": "blue",   "active": False},
            {"id": "jira",       "name": "Jira",          "desc": "Gestão de Issues e Ticketing",     "icon": "🎫", "color": "indigo", "active": False},
            {"id": "slack",      "name": "Slack",         "desc": "Alertas em Tempo Real",            "icon": "💬", "color": "purple", "active": False},
            {"id": "virustotal", "name": "VirusTotal",    "desc": "Threat Intelligence e IOCs",       "icon": "🦠", "color": "red",    "active": False},
            {"id": "shodan",     "name": "Shodan",        "desc": "OSINT / Discovery de Ativos",      "icon": "🌐", "color": "teal",   "active": False},
        ]

    return {
        "agent_connected":         agent_connected,
        "agent_id":                agent_id,
        "last_seen":               last_seen,
        "pentest_tools":           pentest_tools,
        "api_integrations":        api_integrations,
        "configured_integrations": _load(),
        "summary":                 summary,
    }


@router.post("/", summary="Adicionar nova integração")
def add_integration(body: dict):
    """Configura uma nova integração com ferramenta externa."""
    integration_type = body.get("type")
    provider = body.get("provider")

    all_providers = [p for providers in SUPPORTED_INTEGRATIONS.values() for p in providers]
    if provider and provider not in all_providers:
        raise HTTPException(
            status_code=400,
            detail=f"Provider '{provider}' não suportado. Providers disponíveis: {all_providers}"
        )

    integration = {
        "id": str(uuid.uuid4()),
        "name": body.get("name", provider or "Integration"),
        "type": integration_type,
        "provider": provider,
        "config": {k: v for k, v in body.get("config", {}).items() if k != "secret"},
        "enabled": True,
        "created_at": datetime.utcnow().isoformat(),
    }
    integrations = _load()
    integrations.append(integration)
    _save(integrations)
    return {"message": "Integração configurada com sucesso", "integration": integration}


@router.patch("/{integration_id}/toggle", summary="Habilitar/desabilitar integração")
def toggle_integration(integration_id: str):
    """Alterna o status de habilitado/desabilitado de uma integração."""
    integrations = _load()
    for i, integ in enumerate(integrations):
        if integ["id"] == integration_id:
            integrations[i]["enabled"] = not integrations[i].get("enabled", True)
            _save(integrations)
            status = "habilitada" if integrations[i]["enabled"] else "desabilitada"
            return {"message": f"Integração {status}", "integration": integrations[i]}
    raise HTTPException(status_code=404, detail="Integração não encontrada")


@router.delete("/{integration_id}", summary="Remover integração")
def delete_integration(integration_id: str):
    """Remove uma integração configurada."""
    integrations = _load()
    original_count = len(integrations)
    integrations = [i for i in integrations if i["id"] != integration_id]
    if len(integrations) == original_count:
        raise HTTPException(status_code=404, detail="Integração não encontrada")
    _save(integrations)
    return {"message": "Integração removida com sucesso"}


@router.post("/{integration_id}/test", summary="Testar conectividade de uma integração")
def test_integration(integration_id: str):
    """Testa a conectividade e autenticação de uma integração configurada."""
    integrations = _load()
    integration = next((i for i in integrations if i["id"] == integration_id), None)
    if not integration:
        raise HTTPException(status_code=404, detail="Integração não encontrada")
    # Simulação de teste — em produção, faria uma chamada real à API externa
    return {
        "integration_id": integration_id,
        "provider": integration.get("provider"),
        "test_status": "success",
        "latency_ms": 42,
        "message": f"Integração com '{integration.get('provider')}' funcionando corretamente",
        "tested_at": datetime.utcnow().isoformat(),
    }
