"""
PreviSwit AI-ASPM — Router: Reports
Geração e listagem de relatórios executivos e técnicos.
"""
from fastapi import APIRouter, HTTPException
import json
import os
import uuid
from datetime import datetime

router = APIRouter(prefix="/reports", tags=["Reports"])

DATA_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "data", "reports_meta.json")
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "reports")


def _load_meta() -> list:
    if not os.path.exists(DATA_FILE):
        return []
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_meta(data: list) -> None:
    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


@router.get("/", summary="Listar relatórios gerados")
def list_reports():
    """Retorna o histórico de relatórios gerados."""
    reports = _load_meta()
    return {"reports": reports, "total": len(reports)}


@router.post("/generate", summary="Solicitar geração de novo relatório")
def generate_report(body: dict):
    """
    Inicia a geração de um relatório. Suporta tipos: 'executive' e 'technical'.
    O relatório é criado de forma assíncrona e ficará disponível após processamento.
    """
    report_type = body.get("type", "executive")
    asset_id = body.get("asset_id")
    engagement_id = body.get("engagement_id")
    template = body.get("template", "default")
    title = body.get("title", f"Relatório {report_type.capitalize()} — {datetime.now().strftime('%d/%m/%Y')}")

    if report_type not in ("executive", "technical", "compliance"):
        raise HTTPException(status_code=400, detail="Tipo de relatório inválido. Use: executive, technical, compliance")

    report_meta = {
        "id": str(uuid.uuid4()),
        "title": title,
        "type": report_type,
        "template": template,
        "asset_id": asset_id,
        "engagement_id": engagement_id,
        "status": "generating",  # generating, ready, failed
        "format": "html",
        "file_path": None,
        "requested_at": datetime.utcnow().isoformat(),
        "completed_at": None,
    }

    meta_list = _load_meta()
    meta_list.append(report_meta)
    _save_meta(meta_list)

    return {
        "message": "Geração de relatório iniciada",
        "report": report_meta,
        "note": "O relatório estará disponível em /reports/{id} após processamento.",
    }


@router.get("/{report_id}", summary="Obter metadados de um relatório")
def get_report(report_id: str):
    """Retorna os metadados e status de um relatório específico."""
    reports = _load_meta()
    report = next((r for r in reports if r["id"] == report_id), None)
    if not report:
        raise HTTPException(status_code=404, detail="Relatório não encontrado")
    return report


@router.get("/templates/list", summary="Listar templates de relatório")
def list_templates():
    """Retorna os templates de relatório disponíveis."""
    return {
        "templates": [
            {
                "id": "default",
                "name": "Padrão PreviSwit",
                "description": "Template completo com branding PreviSwit",
                "audiences": ["executive", "technical"],
            },
            {
                "id": "ciso",
                "name": "CISO Executive Brief",
                "description": "Relatório conciso para C-Suite: score, tendências e impacto de negócio",
                "audiences": ["executive"],
            },
            {
                "id": "dev_team",
                "name": "Dev Team Report",
                "description": "Relatório técnico com findings detalhados e snippets de código corrigido",
                "audiences": ["technical"],
            },
            {
                "id": "compliance",
                "name": "Compliance Report",
                "description": "Mapeamento para OWASP Top 10, NIST CSF e ISO 27001",
                "audiences": ["compliance"],
            },
        ]
    }
