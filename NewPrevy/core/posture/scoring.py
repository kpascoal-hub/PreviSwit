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
PreviSwit AI-ASPM — core.posture.scoring
=========================================
Exposição de risco, curva de score e saúde de controle.

POR QUE ESTE MÓDULO EXISTE
--------------------------
A fórmula anterior (`api/routers/risk.py`) era:

    score = min(100, sum(pesos) * 0.5)

Com os dados reais (7 CRITICAL + 57 HIGH) isso dá 372.5, clipado em 100.0.
O score estava TRAVADO: corrigir 40 findings ainda deixaria em 100. Um
simulador de investimento em cima disso mostraria "antes 100, depois 100".

A curva aqui nunca satura, é exatamente 0 com zero findings e é estritamente
monotônica — toda correção move o número.

CONVENÇÃO DE SINAL
------------------
**100 = PIOR.** Igual ao contrato antigo de `/risk/score`, preservado para
não quebrar `AssetsPage.jsx`. O frontend inverte para exibição.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from core.posture.normalize import (
    age_multiplier,
    exploit_multiplier,
    is_open,
    severity_of,
)

__all__ = [
    "SLA_DAYS",
    "W_SEV",
    "W_CRIT",
    "SEVERITY_FLOOR",
    "HALF_POINT_CEQ",
    "ALPHA",
    "level_for",
    "exposure",
    "score_from_exposure",
    "control_health",
    "compute_posture",
]

# ── Pesos derivados da política de SLA já declarada ───────────────────────────
#
# NÃO inventar uma segunda tabela de pesos. A organização já afirmou, em
# política (`api/routers/findings.py:SLA_DAYS`), que um CRITICAL deve ser
# corrigido 25.7x mais rápido que um LOW. Isso É uma declaração de urgência
# relativa. Derivar daí significa que mudar a SLA muda o risco de forma
# coerente, e que as duas escalas nunca podem se contradizer.
#
# Import defensivo: `findings.py` importa FastAPI, e este pacote é puro.
# Em contexto de teste isolado o fallback mantém os mesmos números.
try:
    from api.routers.findings import SLA_DAYS  # type: ignore
except Exception:  # pragma: no cover - fallback para uso fora da app
    SLA_DAYS = {"CRITICAL": 7, "HIGH": 30, "MEDIUM": 90, "LOW": 180, "INFO": 365}

_BASE_SLA = SLA_DAYS.get("LOW", 180)

W_SEV: dict[str, float] = {
    sev: (0.0 if sev == "INFO" else _BASE_SLA / days)
    for sev, days in SLA_DAYS.items()
}
# CRITICAL 25.714 · HIGH 6.0 · MEDIUM 2.0 · LOW 1.0 · INFO 0.0

W_CRIT: float = W_SEV.get("CRITICAL", 25.714285714285715)

# ── Calibração da curva ───────────────────────────────────────────────────────

# CEQ ("críticos-equivalentes") no qual o score vale exatamente 50.
#
# Justificativa: com SLA_DAYS[CRITICAL] = 7 e uma vazão realista de ~1
# crítico-equivalente por dia, um backlog de 10 CEQ é ~1.4x a janela de SLA
# do crítico — a organização está estruturalmente incapaz de cumprir a
# própria política. É uma definição defensável de "ponto de virada".
HALF_POINT_CEQ: float = 10.0

# Piso por pior severidade aberta.
#
# Um único CRITICAL isolado dá CEQ=1 -> curva 9.1, que leria "LOW". Registros
# de risco reais usam max-de junto com soma-de: um evento catastrófico não pode
# ser diluído pela média. Como `max()` de duas funções monotônicas continua
# monotônico, o piso não quebra a propriedade principal da curva.
SEVERITY_FLOOR: dict[str, float] = {
    "CRITICAL": 30.0,
    "HIGH": 15.0,
    "MEDIUM": 5.0,
    "LOW": 0.0,
    "INFO": 0.0,
}

# Expoente da lei de potência da saúde de controle.
#
# Fixado por duas âncoras de calibração:
#   um CRITICAL fresco   -> controle em ~40%  (2 ** -4/3     = 0.397)
#   um HIGH fresco       -> controle em ~76%  (1.2333 ** -4/3 = 0.756)
ALPHA: float = 4.0 / 3.0

_BANDS = ((75.0, "CRITICAL"), (50.0, "HIGH"), (25.0, "MEDIUM"))
_SEV_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def level_for(score: float) -> str:
    """Banda de risco. Limiares 75/50/25 — inalterados em relação ao contrato antigo."""
    for threshold, label in _BANDS:
        if score >= threshold:
            return label
    return "LOW"


# ── Exposição ─────────────────────────────────────────────────────────────────

def exposure(
    findings: Iterable[dict],
    kev_ids: frozenset[str] | set[str] | None = None,
    now: datetime | None = None,
) -> dict:
    """
    Exposição agregada `R` e sua decomposição.

    R = Σ  W_SEV[sev] · age_mult · exploit_mult

    R é **aditivo por construção** — é isso que torna o simulador bem-posto.
    O score é não-linear em R, então deltas de score por pacote não seriam
    aditivos e o objetivo do otimizador seria mal definido. Otimiza-se em R;
    a conversão para 0-100 acontece uma única vez, no R residual.

    Devolve `R` (com KEV) e `R_base` (sem KEV) sempre. Sem os dois o score
    ficaria não-reproduzível offline, já que a disponibilidade do feed KEV
    depende de rede.
    """
    now = now or datetime.now(timezone.utc)
    open_findings = [f for f in findings if is_open(f)]

    total = 0.0
    total_base = 0.0
    by_severity: dict[str, int] = {s: 0 for s in _SEV_ORDER}
    per_finding: dict[str, float] = {}

    for f in open_findings:
        sev = severity_of(f)
        w = W_SEV.get(sev, 1.0)
        m_age = age_multiplier(f, SLA_DAYS, now)
        m_exp = exploit_multiplier(f, kev_ids)

        points = w * m_age * m_exp
        total += points
        total_base += w * m_age * exploit_multiplier(f, None)

        by_severity[sev] = by_severity.get(sev, 0) + 1
        fid = f.get("id")
        if fid:
            per_finding[str(fid)] = round(points, 4)

    worst = next((s for s in _SEV_ORDER if by_severity.get(s)), "LOW")

    return {
        "R": round(total, 4),
        "R_base": round(total_base, 4),
        "open_findings": len(open_findings),
        "by_severity": by_severity,
        "worst_severity": worst,
        "per_finding": per_finding,
    }


def score_from_exposure(
    R: float,
    worst_severity: str = "LOW",
    half_point: float = HALF_POINT_CEQ,
) -> dict:
    """
    Converte exposição em score 0-100 pela curva de Hill / Michaelis-Menten.

        CEQ   = R / W_CRIT
        curva = 100 * (1 - 1 / (1 + CEQ / half_point))
        score = max(curva, SEVERITY_FLOOR[pior severidade])

    Propriedades:
      - R = 0            -> score 0.0 exato (sem fudge)
      - CEQ = half_point -> score 50.0 exato
      - CEQ = 100        -> 90.9   |   CEQ = 1000 -> 99.0  (nunca satura)
      - estritamente monotônica: toda correção move o número
    """
    ceq = (R / W_CRIT) if W_CRIT else 0.0
    curve = 100.0 * (1.0 - 1.0 / (1.0 + ceq / half_point)) if half_point > 0 else 0.0

    floor = SEVERITY_FLOOR.get(worst_severity, 0.0) if R > 0 else 0.0
    score = max(curve, floor)

    return {
        "score": round(score, 1),
        "level": level_for(score),
        "critical_equivalents": round(ceq, 2),
        "curve_value": round(curve, 1),
        "floor_applied": floor > curve and R > 0,
        "floor_reason": (
            f"Piso de {floor:.0f} aplicado: existe ao menos um finding {worst_severity} aberto."
            if floor > curve and R > 0 else None
        ),
    }


def control_health(damage: float) -> float:
    """
    Saúde de um controle, 0..1, a partir do dano ponderado acumulado nele.

        p = (1 + D / W_CRIT) ** (-ALPHA)

    Por que lei de potência e não linear:

    1. Exatamente 1.0 (100%) com dano zero. Nunca negativo, nunca zero absoluto
       — sempre há espaço para mostrar melhora.
    2. Livre de escala: cada DOBRO de dano custa ao controle 2**(-4/3) = 60% da
       saúde restante, em qualquer ponto da curva. Dá para explicar isso a um
       CISO em uma frase, e ele consegue conferir.
    3. Dano marginal decrescente reflete a realidade: um controle está quebrado
       ou não. Volume é sinal secundário. Dano linear fazia 20 CVEs custarem 40
       pontos do framework INTEIRO — isso não significa nada.
    """
    if damage <= 0:
        return 1.0
    return (1.0 + damage / W_CRIT) ** (-ALPHA)


# ── Snapshot completo ─────────────────────────────────────────────────────────

def compute_posture(
    findings: Iterable[dict],
    kev_ids: frozenset[str] | set[str] | None = None,
    now: datetime | None = None,
    half_point: float = HALF_POINT_CEQ,
    top_n: int = 10,
) -> dict:
    """
    Postura completa a partir de uma lista de findings JÁ canonicalizados.

    Esta é a única função que o simulador usa para calcular o "depois":

        after = compute_posture(findings_residuais)

    Sem caso especial, sem bookkeeping de delta, sem chance do "depois"
    discordar do que `/posture/snapshot` reportaria quando o trabalho for
    de fato concluído.
    """
    now = now or datetime.now(timezone.utc)
    exp = exposure(findings, kev_ids, now)
    scored = score_from_exposure(exp["R"], exp["worst_severity"], half_point)
    scored_base = score_from_exposure(exp["R_base"], exp["worst_severity"], half_point)

    per_finding = exp["per_finding"]
    open_list = [f for f in findings if is_open(f)]
    ranked = sorted(
        open_list,
        key=lambda f: per_finding.get(str(f.get("id")), 0.0),
        reverse=True,
    )[:top_n]

    top_drivers = [
        {
            "id": f.get("id"),
            "title": f.get("title") or f.get("name"),
            "severity": severity_of(f),
            "tool": f.get("tool"),
            "package": f.get("package"),
            "cve_id": f.get("cve_id"),
            "risk_points": per_finding.get(str(f.get("id")), 0.0),
        }
        for f in ranked
    ]

    return {
        "risk_score": scored["score"],
        "risk_level": scored["level"],
        "risk_score_base": scored_base["score"],
        "exposure_R": exp["R"],
        "exposure_R_base": exp["R_base"],
        "critical_equivalents": scored["critical_equivalents"],
        "floor_applied": scored["floor_applied"],
        "floor_reason": scored["floor_reason"],
        "open_findings": exp["open_findings"],
        "findings_by_severity": exp["by_severity"],
        "worst_severity": exp["worst_severity"],
        "top_drivers": top_drivers,
        "kev_available": kev_ids is not None,
        "calculated_at": now.isoformat(),
        "engine": "posture_v2",
    }
