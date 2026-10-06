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
PreviSwit AI-ASPM — core.posture.packages
==========================================
Agrupamento de findings em pacotes de remediação e modelo de custo.

DEFINIÇÃO DE PACOTE
-------------------
Um pacote é **a unidade de trabalho que um desenvolvedor faz em um PR**.
Não é "um finding" nem "uma família": é uma tarefa.

Isso importa porque o custo real é sublinear no número de findings. As 32 CVEs
do Pillow se resolvem com UM `pip install -U Pillow==12.3.0`. Tratar cada CVE
como item independente daria 32x o custo real e faria o simulador recomendar
a coisa errada.

O Checkov agrupa por `(família, arquivo)` e não só por arquivo: `CKV_SECRET_6`
num Dockerfile é rotacionar segredo e mover para cofre; `CKV_DOCKER_2` é
adicionar um HEALTHCHECK. Trabalho diferente, custo diferente, controle
diferente — pacotes diferentes.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Iterable

from core.posture.normalize import (
    age_multiplier, exploit_multiplier, is_open, normalize_path, severity_of,
)
from core.posture.scoring import SLA_DAYS, W_SEV
from core.posture.taxonomy import FAMILY_LABELS, Family

__all__ = ["EFFORT", "parse_semver", "max_version", "build_packages"]


# ── Modelo de esforço (horas) ─────────────────────────────────────────────────
#
#   horas = (base + per_extra*(n-1) + regressao) * m_break
#
# `per_extra` sublinear é a afirmação econômica central: o custo marginal do
# 2º finding dentro do mesmo pacote é quase zero — você sobe a versão uma vez.
EFFORT: dict[str, dict[str, float]] = {
    Family.VULN_COMPONENTS:        {"base": 2.0, "per_extra": 0.25, "regression": 3.0},
    Family.SECRETS_MGMT:           {"base": 4.0, "per_extra": 1.50, "regression": 1.0},
    Family.SEC_MISCONFIG:          {"base": 1.5, "per_extra": 0.75, "regression": 1.0},
    Family.SUPPLY_CHAIN_INTEGRITY: {"base": 2.0, "per_extra": 0.50, "regression": 1.0},
    Family.INJECTION:              {"base": 3.0, "per_extra": 2.00, "regression": 2.0},
    Family.CRYPTO_FAILURES:        {"base": 4.0, "per_extra": 2.00, "regression": 2.0},
    Family.ACCESS_CONTROL:         {"base": 4.0, "per_extra": 2.50, "regression": 3.0},
    Family.AUTHN_FAILURES:         {"base": 6.0, "per_extra": 3.00, "regression": 3.0},
    Family.LOGGING_MONITORING:     {"base": 3.0, "per_extra": 1.00, "regression": 1.0},
    Family.NETWORK_EXPOSURE:       {"base": 3.0, "per_extra": 1.50, "regression": 2.0},
    Family.DATA_PROTECTION:        {"base": 5.0, "per_extra": 2.00, "regression": 3.0},
    Family.INSECURE_DESIGN:        {"base": 8.0, "per_extra": 3.00, "regression": 4.0},
}

_VER_RE = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def parse_semver(v: str | None) -> tuple[int, int, int]:
    """'12.3.0' -> (12,3,0); '1.0' -> (1,0,0); lixo -> (0,0,0). Sem dependência nova."""
    m = _VER_RE.search(str(v or ""))
    if not m:
        return (0, 0, 0)
    return (int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0))


def max_version(versions: Iterable[str]) -> str:
    """Maior versão de uma lista, por comparação semver."""
    vs = [v for v in versions if v]
    return max(vs, key=parse_semver) if vs else ""


def _break_multiplier(fixed_versions: list[str]) -> tuple[float, str]:
    """
    Multiplicador de risco de breaking change, derivado de evidência.

    O Trivy fornece `fixed_version` mas NÃO `installed_version`. Então só dá
    para inferir um LIMITE INFERIOR do salto: se existe correção em 8.1.0, a
    versão instalada é anterior a 8.1.0. Comparando com o maior `fixed_version`
    exigido, temos o salto mínimo de major.

    Isso é rotulado como limite inferior na resposta, com a derivação exposta.
    """
    if not fixed_versions:
        return 1.0, "sem fixed_version — sem inferência de breaking change"
    lo = min(fixed_versions, key=parse_semver)
    hi = max(fixed_versions, key=parse_semver)
    delta = max(0, parse_semver(hi)[0] - parse_semver(lo)[0])
    m = 1.0 + 0.35 * min(4, delta)
    return round(m, 2), (
        f"salto de >={delta} major version(s) inferido de fixed_version "
        f"mín. {lo} -> máx. {hi} (limite inferior: installed_version não é fornecida pelo Trivy)"
    )


def build_packages(
    findings: Iterable[dict],
    hourly_rate: float,
    usd_brl: float,
    kev_ids: frozenset[str] | set[str] | None = None,
    now: datetime | None = None,
) -> list[dict]:
    """
    Agrupa findings JÁ classificados em pacotes de remediação com custo.

    Regras de agrupamento, primeira que casa vence:
      trivy + package  ->  pkg:{package}          (subir versão uma vez)
      gitleaks         ->  secret:{arquivo}       (rotacionar + cofre)
      checkov / IaC    ->  {familia}:{arquivo}    (editar aquele arquivo)
      semgrep          ->  code:{familia}:{prefixo da regra}
      fallback         ->  {familia}:{tool}
    """
    now = now or datetime.now(timezone.utc)
    groups: dict[str, dict] = {}

    for f in findings:
        if not is_open(f):
            continue

        tool = str(f.get("tool") or "").strip().lower()
        fam = f.get("_family") or Family.INSECURE_DESIGN
        pkg_name = str(f.get("package") or "").strip()
        path = normalize_path(f.get("endpoint"))

        if tool == "trivy" and pkg_name:
            key = f"pkg:{pkg_name}"
            kind = "dependency_upgrade"
        elif tool == "gitleaks":
            key = f"secret:{path or 'repo'}"
            kind = "secret_rotation"
        elif tool == "checkov":
            key = f"{fam.lower()}:{path or 'repo'}"
            kind = "iac_fix"
        elif tool == "semgrep":
            prefix = ".".join(str(f.get("name") or "").split(".")[:3]) or fam.lower()
            key = f"code:{fam}:{prefix}"
            kind = "code_change"
        else:
            key = f"{fam.lower()}:{tool or 'unknown'}"
            kind = "other"

        g = groups.setdefault(key, {
            "id": key, "kind": kind, "family": fam,
            "findings": [], "fixed_versions": [], "package": pkg_name or None,
            "file": path or None,
        })
        g["findings"].append(f)
        fv = str(f.get("fixed_version") or "").strip()
        if fv:
            g["fixed_versions"].append(fv)

    out: list[dict] = []
    for key, g in groups.items():
        fs = g["findings"]
        n = len(fs)
        fam = g["family"]
        eff = EFFORT.get(fam, EFFORT[Family.INSECURE_DESIGN])

        m_break, break_note = (
            _break_multiplier(g["fixed_versions"])
            if g["kind"] == "dependency_upgrade" else (1.0, "não aplicável")
        )

        base_h = eff["base"]
        extra_h = eff["per_extra"] * (n - 1)
        regr_h = eff["regression"]
        hours = round((base_h + extra_h + regr_h) * m_break, 2)
        cost_brl = round(hours * hourly_rate, 2)
        cost_usd = round(cost_brl / usd_brl, 2) if usd_brl else 0.0

        risk_points = sum(
            W_SEV.get(severity_of(f), 1.0)
            * age_multiplier(f, SLA_DAYS, now)
            * exploit_multiplier(f, kev_ids)
            for f in fs
        )

        sev_counts: dict[str, int] = {}
        for f in fs:
            s = severity_of(f)
            sev_counts[s] = sev_counts.get(s, 0) + 1

        worst = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if sev_counts.get(s)), "LOW")
        target = max_version(g["fixed_versions"]) if g["kind"] == "dependency_upgrade" else ""

        # Título legível, no idioma do painel.
        if g["kind"] == "dependency_upgrade":
            crit = sev_counts.get("CRITICAL", 0)
            title = f"Atualizar {g['package']} → {target} ({n} CVE{'s' if n != 1 else ''}"
            title += f", {crit} CRITICAL)" if crit else ")"
        elif g["kind"] == "secret_rotation":
            title = f"Rotacionar segredos em {g['file']} ({n} ocorrência{'s' if n != 1 else ''})"
        elif g["kind"] == "iac_fix":
            title = f"{FAMILY_LABELS.get(fam, fam)} em {g['file']} ({n} check{'s' if n != 1 else ''})"
        else:
            title = f"{FAMILY_LABELS.get(fam, fam)} ({n} finding{'s' if n != 1 else ''})"

        assumptions = [
            f"Base {base_h}h + {eff['per_extra']}h por finding adicional "
            f"(custo marginal decrescente: a correção é aplicada uma única vez).",
            f"{regr_h}h de teste de regressão.",
        ]
        if m_break > 1.0:
            assumptions.append(f"Multiplicador de breaking change {m_break} — {break_note}.")
        assumptions.append(f"Taxa R$ {hourly_rate:.2f}/h (configurável em /posture/config).")
        assumptions.append("NÃO inclui licenças, infraestrutura, downtime ou custo de oportunidade.")

        out.append({
            "id": key,
            "title": title,
            "kind": g["kind"],
            "family": fam,
            "family_label": FAMILY_LABELS.get(fam, fam),
            "package": g["package"],
            "file": g["file"],
            "target_version": target or None,
            "findings_count": n,
            "finding_ids": [f.get("id") for f in fs if f.get("id")],
            "severity_counts": sev_counts,
            "worst_severity": worst,
            "hours": hours,
            "cost": {"brl": cost_brl, "usd": cost_usd},
            "risk_points": round(risk_points, 2),
            "efficiency_per_1k": round(risk_points / (cost_brl / 1000.0), 2) if cost_brl > 0 else 0.0,
            "estimate": {
                "method": "effort_hours_x_blended_rate",
                "breakdown": {
                    "base": base_h, "per_extra_total": round(extra_h, 2),
                    "regression": regr_h, "m_break": m_break,
                },
                "assumptions": assumptions,
                "confidence": "estimate_not_quote",
            },
        })

    out.sort(key=lambda p: (-p["efficiency_per_1k"], -p["risk_points"], p["id"]))
    return out
