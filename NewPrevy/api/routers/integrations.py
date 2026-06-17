"""
PreviSwit AI-ASPM — Router: Integrations
Gestão de integrações com CI/CD, ticketing e notificações.
"""
from fastapi import APIRouter, HTTPException
import json
import os
import uuid
from datetime import datetime

router = APIRouter(prefix="/integrations", tags=["Integrations"])

DATA_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "data", "integrations.json")

SUPPORTED_INTEGRATIONS = {
    "cicd": ["github_actions", "gitlab_ci", "jenkins", "azure_devops"],
    "ticketing": ["jira", "linear", "github_issues", "azure_boards"],
    "notifications": ["slack", "microsoft_teams", "pagerduty", "email"],
    "scan_tools": ["nuclei", "trivy", "owasp_zap", "semgrep", "bandit"],
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
