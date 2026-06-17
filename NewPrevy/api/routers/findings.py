"""
PreviSwit AI-ASPM — Router: Findings (Central de Triagem)
CRUD de vulnerabilidades, deduplicação, ciclo de vida e SLA.
"""
from fastapi import APIRouter, HTTPException, Query, status
from typing import List, Optional
import json
import os
import uuid
from datetime import datetime, timedelta

router = APIRouter(prefix="/findings", tags=["Findings & Triage"])

DATA_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "data", "findings.json")

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# SLA padrão por severidade (dias)
SLA_DAYS = {"CRITICAL": 7, "HIGH": 30, "MEDIUM": 90, "LOW": 180, "INFO": 365}


def _load() -> List[dict]:
    if not os.path.exists(DATA_FILE):
        return []
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _save(data: List[dict]) -> None:
    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


def _enrich_sla(finding: dict) -> dict:
    """Calcula e adiciona informações de SLA ao finding."""
    severity = finding.get("severity", "LOW").upper()
    sla_days = SLA_DAYS.get(severity, 180)
    created = datetime.fromisoformat(finding.get("created_at", datetime.utcnow().isoformat()))
    deadline = created + timedelta(days=sla_days)
    days_remaining = (deadline - datetime.utcnow()).days
    finding["sla"] = {
        "deadline": deadline.isoformat(),
        "days_remaining": days_remaining,
        "is_overdue": days_remaining < 0,
        "sla_days": sla_days,
    }
    return finding


@router.get("/", summary="Listar findings com filtros")
def list_findings(
    severity: Optional[str] = Query(None, description="CRITICAL, HIGH, MEDIUM, LOW, INFO"),
    status: Optional[str] = Query(None, description="open, in_remediation, verified, closed, false_positive"),
    asset_id: Optional[str] = Query(None),
    engagement_id: Optional[str] = Query(None),
    overdue_only: bool = Query(False),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
):
    """Retorna findings com filtros avançados e paginação."""
    findings = _load()

    if severity:
        findings = [f for f in findings if f.get("severity", "").upper() == severity.upper()]
    if status:
        findings = [f for f in findings if f.get("status") == status]
    if asset_id:
        findings = [f for f in findings if f.get("asset_id") == asset_id]
    if engagement_id:
        findings = [f for f in findings if f.get("engagement_id") == engagement_id]

    # Enriquece com SLA
    findings = [_enrich_sla(f) for f in findings]

    if overdue_only:
        findings = [f for f in findings if f.get("sla", {}).get("is_overdue")]

    # Ordenação: mais crítico primeiro
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO").upper(), 4))

    total = len(findings)
    start = (page - 1) * page_size
    paginated = findings[start: start + page_size]

    return {
        "findings": paginated,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
    }


@router.post("/", status_code=status.HTTP_201_CREATED, summary="Registrar novo finding")
def create_finding(body: dict):
    """Registra uma nova vulnerabilidade encontrada por um scan."""
    findings = _load()
    finding = {
        "id": str(uuid.uuid4()),
        "title": body.get("title", "Untitled Finding"),
        "description": body.get("description", ""),
        "severity": body.get("severity", "MEDIUM").upper(),
        "status": "open",
        "asset_id": body.get("asset_id"),
        "engagement_id": body.get("engagement_id"),
        "cve_id": body.get("cve_id"),
        "cvss_score": body.get("cvss_score"),
        "url": body.get("url"),
        "endpoint": body.get("endpoint"),
        "tool": body.get("tool"),
        "raw_output": body.get("raw_output"),
        "ai_remediation": None,
        "is_duplicate": False,
        "duplicate_of": None,
        "false_positive": False,
        "false_positive_reason": None,
        "tags": body.get("tags", []),
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
    }
    findings.append(finding)
    _save(findings)
    return _enrich_sla(finding)


@router.get("/stats/summary", summary="Resumo estatístico dos findings")
def get_findings_summary():
    """Retorna contadores e métricas agregadas dos findings."""
    findings = _load()
    summary = {
        "total": len(findings),
        "by_severity": {s: 0 for s in SEVERITY_ORDER},
        "by_status": {},
        "overdue": 0,
        "false_positives": 0,
        "duplicates": 0,
    }
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        if sev in summary["by_severity"]:
            summary["by_severity"][sev] += 1
        st = f.get("status", "open")
        summary["by_status"][st] = summary["by_status"].get(st, 0) + 1
        if f.get("false_positive"):
            summary["false_positives"] += 1
        if f.get("is_duplicate"):
            summary["duplicates"] += 1
        enriched = _enrich_sla(f)
        if enriched.get("sla", {}).get("is_overdue") and f.get("status") not in ("closed", "false_positive"):
            summary["overdue"] += 1
    return summary


@router.get("/{finding_id}", summary="Detalhe de um finding")
def get_finding(finding_id: str):
    """Retorna os detalhes completos de um finding específico."""
    findings = _load()
    finding = next((f for f in findings if f["id"] == finding_id), None)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding não encontrado")
    return _enrich_sla(finding)


@router.patch("/{finding_id}/status", summary="Atualizar status do finding")
def update_finding_status(finding_id: str, body: dict):
    """Atualiza o status do ciclo de vida de um finding."""
    valid_statuses = ["open", "in_remediation", "verified", "closed", "false_positive"]
    new_status = body.get("status")
    if new_status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Status inválido. Use: {valid_statuses}")
    findings = _load()
    for i, f in enumerate(findings):
        if f["id"] == finding_id:
            findings[i]["status"] = new_status
            findings[i]["updated_at"] = datetime.utcnow().isoformat()
            if new_status == "false_positive":
                findings[i]["false_positive"] = True
                findings[i]["false_positive_reason"] = body.get("reason", "")
            _save(findings)
            return _enrich_sla(findings[i])
    raise HTTPException(status_code=404, detail="Finding não encontrado")


@router.get("/triage/queue", summary="Fila de triagem por IA")
def get_triage_queue():
    """Retorna findings abertos ordenados por prioridade para triagem."""
    findings = _load()
    queue = [
        _enrich_sla(f) for f in findings
        if f.get("status") == "open" and not f.get("is_duplicate") and not f.get("false_positive")
    ]
    queue.sort(key=lambda f: (
        SEVERITY_ORDER.get(f.get("severity", "INFO").upper(), 4),
        not f.get("sla", {}).get("is_overdue", False)
    ))
    return {"queue": queue, "total": len(queue)}
