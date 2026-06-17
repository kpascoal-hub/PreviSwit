"""
PreviSwit AI-ASPM — Router: Risk & Posture Metrics
Score de risco evolutivo, compliance e benchmarking.
"""
from fastapi import APIRouter
import json
import os
from datetime import datetime

router = APIRouter(prefix="/risk", tags=["Risk & Posture"])

DATA_FILE_FINDINGS = os.path.join(os.path.dirname(__file__), "..", "..", "data", "findings.json")
DATA_FILE_RISK = os.path.join(os.path.dirname(__file__), "..", "..", "data", "risk_history.json")

SEVERITY_WEIGHTS = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 3, "LOW": 1, "INFO": 0}

COMPLIANCE_FRAMEWORKS = {
    "OWASP_TOP_10_2021": {
        "name": "OWASP Top 10 2021",
        "categories": [
            "A01:2021 - Broken Access Control",
            "A02:2021 - Cryptographic Failures",
            "A03:2021 - Injection",
            "A04:2021 - Insecure Design",
            "A05:2021 - Security Misconfiguration",
            "A06:2021 - Vulnerable and Outdated Components",
            "A07:2021 - Identification and Authentication Failures",
            "A08:2021 - Software and Data Integrity Failures",
            "A09:2021 - Security Logging and Monitoring Failures",
            "A10:2021 - Server-Side Request Forgery",
        ],
    },
    "NIST_CSF": {
        "name": "NIST Cybersecurity Framework",
        "functions": ["Identify", "Protect", "Detect", "Respond", "Recover"],
    },
}


def _load_findings() -> list:
    if not os.path.exists(DATA_FILE_FINDINGS):
        return []
    with open(DATA_FILE_FINDINGS, "r", encoding="utf-8") as f:
        return json.load(f)


def _load_risk_history() -> list:
    if not os.path.exists(DATA_FILE_RISK):
        return []
    with open(DATA_FILE_RISK, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_risk_snapshot(score: float, level: str) -> None:
    history = _load_risk_history()
    history.append({
        "score": score,
        "level": level,
        "recorded_at": datetime.utcnow().isoformat(),
    })
    # Mantém apenas os últimos 90 snapshots
    history = history[-90:]
    os.makedirs(os.path.dirname(DATA_FILE_RISK), exist_ok=True)
    with open(DATA_FILE_RISK, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2, default=str)


def _calculate_score(findings: list) -> dict:
    """Calcula o score de risco global (0-100) a partir dos findings abertos."""
    open_findings = [f for f in findings if f.get("status") not in ("closed", "false_positive")]
    raw_score = sum(SEVERITY_WEIGHTS.get(f.get("severity", "LOW").upper(), 0) for f in open_findings)
    # Normaliza para 0-100 (100 = máximo risco)
    score = min(100.0, round(raw_score * 0.5, 1))
    if score >= 75:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 25:
        level = "MEDIUM"
    else:
        level = "LOW"
    return {"score": score, "level": level, "open_findings": len(open_findings)}


@router.get("/score", summary="Score de risco global atual")
def get_risk_score():
    """Calcula e retorna o score de risco global da organização com base nos findings abertos."""
    findings = _load_findings()
    result = _calculate_score(findings)
    _save_risk_snapshot(result["score"], result["level"])
    return {
        **result,
        "timestamp": datetime.utcnow().isoformat(),
        "description": (
            "Nenhuma vulnerabilidade crítica aberta." if result["score"] < 25 else
            "Vulnerabilidades de alto risco requerem atenção." if result["score"] < 50 else
            "Risco elevado: ação imediata recomendada." if result["score"] < 75 else
            "🔴 Risco crítico: intervenção de emergência necessária."
        ),
    }


@router.get("/history", summary="Histórico de evolução do score de risco")
def get_risk_history(days: int = 30):
    """Retorna a série temporal do score de risco para gráficos de tendência."""
    history = _load_risk_history()
    # Filtra pelos últimos N dias
    from datetime import timedelta
    cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
    filtered = [h for h in history if h.get("recorded_at", "") >= cutoff]
    return {
        "history": filtered,
        "total_snapshots": len(filtered),
        "period_days": days,
    }


@router.get("/compliance", summary="Status de conformidade com frameworks")
def get_compliance():
    """Retorna o status de conformidade com OWASP Top 10, NIST CSF e outros frameworks."""
    findings = _load_findings()
    open_findings = [f for f in findings if f.get("status") not in ("closed", "false_positive")]
    total_open = len(open_findings)

    # Compliance score simplificado baseado no volume de findings abertos
    base_compliance = max(0, 100 - total_open * 2)

    return {
        "frameworks": {
            "OWASP_TOP_10_2021": {
                "name": "OWASP Top 10 2021",
                "compliance_percentage": round(base_compliance * 0.9, 1),
                "status": "compliant" if base_compliance > 80 else "partial" if base_compliance > 50 else "non_compliant",
                "open_findings_mapped": total_open,
            },
            "NIST_CSF": {
                "name": "NIST Cybersecurity Framework",
                "compliance_percentage": round(base_compliance * 0.85, 1),
                "status": "compliant" if base_compliance > 80 else "partial" if base_compliance > 50 else "non_compliant",
            },
        },
        "overall_compliance": round(base_compliance * 0.875, 1),
        "calculated_at": datetime.utcnow().isoformat(),
        "note": "Compliance calculado com base nos findings abertos. Integração com frameworks completos disponível via upgrade.",
    }


@router.get("/summary", summary="Resumo executivo de risco")
def get_risk_summary():
    """Retorna um resumo executivo completo: score, compliance e tendência."""
    findings = _load_findings()
    score_data = _calculate_score(findings)
    history = _load_risk_history()

    # Tendência: compara score atual com 7 dias atrás
    from datetime import timedelta
    week_ago = (datetime.utcnow() - timedelta(days=7)).isoformat()
    week_old = [h for h in history if h.get("recorded_at", "") < week_ago]
    trend = "stable"
    if week_old:
        old_score = week_old[-1].get("score", score_data["score"])
        if score_data["score"] > old_score + 5:
            trend = "worsening"
        elif score_data["score"] < old_score - 5:
            trend = "improving"

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        if f.get("status") not in ("closed", "false_positive"):
            sev = f.get("severity", "LOW").upper()
            if sev in counts:
                counts[sev] += 1

    return {
        "risk_score": score_data["score"],
        "risk_level": score_data["level"],
        "trend": trend,
        "open_findings": score_data["open_findings"],
        "findings_by_severity": counts,
        "total_findings": len(findings),
        "closed_findings": len([f for f in findings if f.get("status") == "closed"]),
        "calculated_at": datetime.utcnow().isoformat(),
    }
