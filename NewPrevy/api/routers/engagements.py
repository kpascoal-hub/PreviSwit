"""
PreviSwit AI-ASPM — Router: Engagements & Scans
Histórico de scans, instâncias de engajamento e agendamentos.
"""
from fastapi import APIRouter, HTTPException, status
from typing import List
import json
import os
import uuid
from datetime import datetime

router = APIRouter(prefix="/engagements", tags=["Engagements & Scans"])

DATA_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "data", "engagements.json")


def _load() -> List[dict]:
    if not os.path.exists(DATA_FILE):
        return []
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _save(data: List[dict]) -> None:
    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


@router.get("/", summary="Listar todos os engajamentos")
def list_engagements(asset_id: str | None = None, status: str | None = None):
    """Retorna o histórico completo de scans/engajamentos com filtros opcionais."""
    engagements = _load()
    if asset_id:
        engagements = [e for e in engagements if e.get("asset_id") == asset_id]
    if status:
        engagements = [e for e in engagements if e.get("status") == status]
    return {"engagements": engagements, "total": len(engagements)}


@router.post("/", status_code=status.HTTP_201_CREATED, summary="Registrar novo engajamento")
def create_engagement(body: dict):
    """Cria um registro de engajamento (scan) com metadados e resultados."""
    engagements = _load()
    engagement = {
        "id": str(uuid.uuid4()),
        "asset_id": body.get("asset_id"),
        "target": body.get("target", ""),
        "pipeline": body.get("pipeline", "all"),
        "status": body.get("status", "pending"),  # pending, running, completed, failed
        "findings_count": body.get("findings_count", {"critical": 0, "high": 0, "medium": 0, "low": 0}),
        "duration_seconds": body.get("duration_seconds", 0),
        "scan_tools_used": body.get("scan_tools_used", []),
        "report_path": body.get("report_path"),
        "started_at": body.get("started_at", datetime.utcnow().isoformat()),
        "completed_at": body.get("completed_at"),
        "created_at": datetime.utcnow().isoformat(),
    }
    engagements.append(engagement)
    _save(engagements)
    return engagement


@router.get("/{engagement_id}", summary="Detalhe de um engajamento")
def get_engagement(engagement_id: str):
    """Retorna os detalhes completos de um engajamento específico."""
    engagements = _load()
    eng = next((e for e in engagements if e["id"] == engagement_id), None)
    if not eng:
        raise HTTPException(status_code=404, detail="Engajamento não encontrado")
    return eng


@router.patch("/{engagement_id}/status", summary="Atualizar status do engajamento")
def update_engagement_status(engagement_id: str, body: dict):
    """Atualiza o status de um engajamento (ex: de 'running' para 'completed')."""
    engagements = _load()
    for i, e in enumerate(engagements):
        if e["id"] == engagement_id:
            engagements[i]["status"] = body.get("status", e["status"])
            if body.get("status") == "completed":
                engagements[i]["completed_at"] = datetime.utcnow().isoformat()
            engagements[i].update({k: v for k, v in body.items() if k != "status"})
            _save(engagements)
            return engagements[i]
    raise HTTPException(status_code=404, detail="Engajamento não encontrado")


@router.get("/stats/summary", summary="Estatísticas gerais de scans")
def get_scan_stats():
    """Retorna métricas agregadas sobre todos os engajamentos."""
    engagements = _load()
    total = len(engagements)
    completed = sum(1 for e in engagements if e.get("status") == "completed")
    failed = sum(1 for e in engagements if e.get("status") == "failed")
    running = sum(1 for e in engagements if e.get("status") == "running")
    return {
        "total": total,
        "completed": completed,
        "failed": failed,
        "running": running,
        "pending": total - completed - failed - running,
    }
