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
PreviSwit AI-ASPM — Router: Risk & Posture Metrics
===================================================
Contrato legado, delegando para o engine `core.posture`.

MIGRAÇÃO (ver core/posture/scoring.py para a matemática)
--------------------------------------------------------
A fórmula anterior era `min(100, sum(pesos) * 0.5)`, que SATURAVA em 100 com
os dados reais e ficava travada: corrigir 40 findings não movia o número.
Agora delega para a curva de Hill, que nunca satura.

Caminhos e chaves de resposta preservados — `AssetsPage.jsx` consome
`/risk/score` e lê `.score` e `.level`. Os VALORES mudam (era 100.0 fixo,
agora acompanha a realidade), que é justamente o objetivo.

O EFEITO COLATERAL DE ESCRITA FOI REMOVIDO. `GET /risk/score` gravava um
snapshot em `risk_history.json` a cada chamada — um GET não pode mutar estado,
e era isso que enchia o histórico de ruído (16 amostras num dia, 40 em outro).
A escrita agora é `POST /api/v1/posture/snapshot/record`, com upsert por dia.

Para o painel completo (7 frameworks, radar, simulador), use `/api/v1/posture/*`.
"""
from fastapi import APIRouter
from datetime import datetime, timedelta, timezone
import os

from core.posture.normalize import canonicalize
from core.posture.scoring import W_SEV, compute_posture  # noqa: F401 (W_SEV re-exportado)
from core.posture.store import load_json
from core.posture.taxonomy import classify_all

router = APIRouter(prefix="/risk", tags=["Risk & Posture"])

_DATA = os.path.join(os.path.dirname(__file__), "..", "..", "data")
DATA_FILE_FINDINGS = os.path.join(_DATA, "findings.json")
DATA_FILE_RISK = os.path.join(_DATA, "risk_history.json")


def _load_findings() -> list:
    data = load_json(DATA_FILE_FINDINGS, [])
    return data if isinstance(data, list) else []


def _posture() -> dict:
    """Pipeline compartilhado: carrega, canonicaliza, classifica, pontua."""
    unique, dedup = canonicalize(_load_findings())
    enriched, _ = classify_all(unique)
    snap = compute_posture(enriched)
    return {**snap, "deduplication": dedup, "findings": enriched}


@router.get("/score", summary="Score de risco global atual")
def get_risk_score():
    """
    Score de risco 0-100 (100 = pior). Contrato inalterado.

    Sem efeito colateral: ver nota de migração no topo do módulo.
    """
    p = _posture()
    score = p["risk_score"]
    return {
        "score": score,
        "level": p["risk_level"],
        "open_findings": p["open_findings"],
        "timestamp": p["calculated_at"],
        "description": (
            "Nenhuma vulnerabilidade crítica aberta." if score < 25 else
            "Vulnerabilidades de alto risco requerem atenção." if score < 50 else
            "Risco elevado: ação imediata recomendada." if score < 75 else
            "🔴 Risco crítico: intervenção de emergência necessária."
        ),
        # Campos aditivos — não quebram consumidores existentes.
        "exposure_R": p["exposure_R"],
        "critical_equivalents": p["critical_equivalents"],
        "findings_by_severity": p["findings_by_severity"],
        "deduplication": p["deduplication"],
        "engine": "posture_v2",
    }


@router.get("/history", summary="Histórico de evolução do score de risco")
def get_risk_history(days: int = 30, bucket: str = "day"):
    """
    Série temporal do score. `bucket=day` (padrão) colapsa para um ponto por
    dia, último valor vence — esconde o ruído histórico sem migrar o arquivo.
    Use `bucket=raw` para as amostras brutas.
    """
    history = load_json(DATA_FILE_RISK, []) or []
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    rows = [h for h in history if str(h.get("recorded_at", "")) >= cutoff]

    if bucket == "day":
        by_day: dict[str, dict] = {}
        for h in rows:
            by_day[str(h.get("recorded_at", ""))[:10]] = h
        rows = [
            {**v, "date": k, "date_label": f"{k[8:10]}/{k[5:7]}"}
            for k, v in sorted(by_day.items())
        ]

    return {
        "history": rows,
        "total_snapshots": len(rows),
        "period_days": days,
        "bucket": bucket,
    }


@router.get("/compliance", summary="[Depreciado] Use /api/v1/posture/compliance",
            deprecated=True)
def get_compliance():
    """
    Alias depreciado.

    A implementação anterior calculava `max(0, 100 - total_open * 2)` vezes
    fatores de ajuste fixos (0.9 / 0.85 / 0.875) — não era percentual de coisa
    nenhuma, e com 64 findings retornava 0 em todos os frameworks.

    Agora remapeia a saída real do engine para o envelope antigo. O endpoint
    sucessor cobre 7 frameworks com mapeamento determinístico por controle.
    """
    from core.posture.frameworks import compute_compliance

    p = _posture()
    tools = sorted({
        str(f.get("tool") or "").strip().lower()
        for f in p["findings"] if f.get("tool")
    })
    real = compute_compliance(p["findings"], tools)
    fws = real["frameworks"]

    def envelope(key: str) -> dict:
        fw = fws.get(key, {})
        return {
            "name": fw.get("name"),
            "compliance_percentage": fw.get("compliance_percentage", 0.0),
            "status": fw.get("status", "not_assessed"),
            "open_findings_mapped": p["open_findings"],
            "in_scope_controls": fw.get("in_scope_controls", 0),
            "catalog_total_controls": fw.get("catalog_total_controls", 0),
        }

    return {
        "frameworks": {
            "OWASP_TOP_10_2021": envelope("OWASP_TOP_10_2021"),
            "NIST_CSF": envelope("NIST_CSF_2_0"),
        },
        "overall_compliance": real["overall_compliance"],
        "calculated_at": real["calculated_at"],
        "deprecated": True,
        "successor": "/api/v1/posture/compliance",
        "note": (
            "Endpoint mantido por compatibilidade. O sucessor cobre LGPD, SOC 2, "
            "ISO 27001, OWASP, NIST CSF, PCI DSS e CIS com mapeamento por controle "
            "e escopo de cobertura explícito."
        ),
    }


@router.get("/summary", summary="Resumo executivo de risco")
def get_risk_summary():
    """Score, tendência e distribuição por severidade."""
    p = _posture()
    history = load_json(DATA_FILE_RISK, []) or []

    # Tendência contra o valor diário mais próximo de 7 dias atrás.
    # A versão anterior usava `week_old[-1]`, uma amostra intradiária arbitrária
    # de um arquivo ruidoso.
    by_day: dict[str, float] = {}
    for h in history:
        stamp = str(h.get("recorded_at", ""))
        if stamp:
            by_day[stamp[:10]] = float(h.get("score") or 0)

    week_ago = (datetime.now(timezone.utc) - timedelta(days=7)).date().isoformat()
    older = sorted((d for d in by_day if d <= week_ago), reverse=True)

    trend = "stable"
    if older:
        old_score = by_day[older[0]]
        if p["risk_score"] > old_score + 5:
            trend = "worsening"
        elif p["risk_score"] < old_score - 5:
            trend = "improving"

    findings = p["findings"]
    return {
        "risk_score": p["risk_score"],
        "risk_level": p["risk_level"],
        "trend": trend,
        "open_findings": p["open_findings"],
        "findings_by_severity": p["findings_by_severity"],
        "total_findings": len(findings),
        "closed_findings": len([
            f for f in findings if str(f.get("status") or "").lower() == "closed"
        ]),
        "calculated_at": p["calculated_at"],
        "engine": "posture_v2",
    }
