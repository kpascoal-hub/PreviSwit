"""
PreviSwit AI-ASPM — Router: Assets & Products
Gestão de inventário de ativos digitais e produtos rastreados.
"""
from fastapi import APIRouter, HTTPException, status
from typing import List
import json
import os
import uuid
from datetime import datetime

router = APIRouter(prefix="/assets", tags=["Assets & Products"])

DATA_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "data", "assets.json")


def _load() -> List[dict]:
    if not os.path.exists(DATA_FILE):
        return []
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _save(data: List[dict]) -> None:
    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


@router.get("/", summary="Listar todos os ativos")
def list_assets():
    """Retorna o inventário completo de ativos/produtos."""
    return {"assets": _load(), "total": len(_load())}


@router.post("/", status_code=status.HTTP_201_CREATED, summary="Criar novo ativo")
def create_asset(body: dict):
    """Registra um novo ativo/produto na plataforma."""
    assets = _load()
    asset = {
        "id": str(uuid.uuid4()),
        "name": body.get("name", "Unnamed Asset"),
        "description": body.get("description", ""),
        "url": body.get("url", ""),
        "technology_stack": body.get("technology_stack", []),
        "risk_score": 0,
        "status": "active",
        "findings_count": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
    }
    assets.append(asset)
    _save(assets)
    return asset


@router.get("/{asset_id}", summary="Detalhe de um ativo")
def get_asset(asset_id: str):
    """Retorna os detalhes completos de um ativo, incluindo histórico de scans."""
    assets = _load()
    asset = next((a for a in assets if a["id"] == asset_id), None)
    if not asset:
        raise HTTPException(status_code=404, detail="Ativo não encontrado")
    return asset


@router.put("/{asset_id}", summary="Atualizar ativo")
def update_asset(asset_id: str, body: dict):
    """Atualiza informações de um ativo existente."""
    assets = _load()
    for i, a in enumerate(assets):
        if a["id"] == asset_id:
            assets[i].update({**body, "updated_at": datetime.utcnow().isoformat()})
            _save(assets)
            return assets[i]
    raise HTTPException(status_code=404, detail="Ativo não encontrado")


@router.delete("/{asset_id}", summary="Remover ativo")
def delete_asset(asset_id: str):
    """Remove um ativo do inventário."""
    assets = _load()
    original_count = len(assets)
    assets = [a for a in assets if a["id"] != asset_id]
    if len(assets) == original_count:
        raise HTTPException(status_code=404, detail="Ativo não encontrado")
    _save(assets)
    return {"message": "Ativo removido com sucesso"}


@router.get("/{asset_id}/attack-surface", summary="Superfície de ataque do ativo")
def get_attack_surface(asset_id: str):
    """Retorna os endpoints mapeados e expostos para um ativo."""
    assets = _load()
    asset = next((a for a in assets if a["id"] == asset_id), None)
    if not asset:
        raise HTTPException(status_code=404, detail="Ativo não encontrado")
    return {
        "asset_id": asset_id,
        "asset_name": asset.get("name"),
        "endpoints": asset.get("endpoints", []),
        "open_ports": asset.get("open_ports", []),
        "subdomains": asset.get("subdomains", []),
    }
