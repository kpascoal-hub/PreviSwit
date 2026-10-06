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
PreviSwit AI-ASPM — core.posture.simulator
===========================================
Simulador de investimento: "coloca R$ 20.000 — o que melhorar, e por quê?"

POR QUE OTIMIZAR EM `R` E NÃO EM SCORE
--------------------------------------
O score é NÃO-LINEAR em R (curva de Hill). Logo, o delta de score de dois
pacotes não é a soma dos deltas individuais, e "maximizar a soma dos deltas de
score" seria um objetivo mal definido.

`R` é **aditivo por construção**. Então: otimiza-se em R, e a conversão para
0-100 acontece UMA ÚNICA VEZ, no R residual. Essa é a justificativa matemática
do endpoint inteiro, e ela vai explícita em `optimizer.note`.

POR QUE KNAPSACK DP E NÃO GREEDY
--------------------------------
Não é preciosismo. Greedy erra de forma comprovável neste dataset: ele gasta o
orçamento em itens pequenos e eficientes e depois não tem espaço para o item
grande que domina tudo (Pillow). O `heuristic_baseline` na resposta demonstra
o ganho em cada simulação — não é alegação, é número.
"""
from __future__ import annotations

from datetime import datetime, timezone
from math import ceil
from typing import Iterable

from core.posture.scoring import compute_posture, score_from_exposure

__all__ = ["knapsack", "greedy", "simulate"]


def knapsack(costs: list[float], values: list[float], budget: float, bucket: float) -> tuple[list[int], float]:
    """
    Knapsack 0/1 exato por programação dinâmica.

    Custos são discretizados em buckets, ARREDONDADOS PARA CIMA — nunca
    subestimar o preço. Com <=50 pacotes e orçamento de R$ 20.000 em buckets de
    R$ 50 são 400 posições: ~20 mil operações, sub-milissegundo.

    Devolve `(indices_escolhidos, valor_total)`.
    """
    if budget <= 0 or not costs:
        return [], 0.0

    B = int(budget // bucket)
    if B <= 0:
        return [], 0.0

    w = [max(1, ceil(c / bucket)) for c in costs]
    dp = [0.0] * (B + 1)
    keep = [[False] * (B + 1) for _ in costs]

    for i, (wi, vi) in enumerate(zip(w, values)):
        if wi > B:
            continue
        for b in range(B, wi - 1, -1):
            cand = dp[b - wi] + vi
            if cand > dp[b] + 1e-9:
                dp[b] = cand
                keep[i][b] = True

    b, chosen = B, []
    for i in range(len(costs) - 1, -1, -1):
        if keep[i][b]:
            chosen.append(i)
            b -= w[i]

    return sorted(chosen), dp[B]


def greedy(costs: list[float], values: list[float], budget: float) -> tuple[list[int], float]:
    """
    Baseline guloso por razão valor/custo. Existe só para comparação: a resposta
    mostra quanto o DP ganhou dele.
    """
    order = sorted(
        range(len(costs)),
        key=lambda i: (-(values[i] / costs[i]) if costs[i] > 0 else 0, costs[i], i),
    )
    spent, total, chosen = 0.0, 0.0, []
    for i in order:
        if spent + costs[i] <= budget:
            chosen.append(i)
            spent += costs[i]
            total += values[i]
    return sorted(chosen), total


def simulate(
    findings: Iterable[dict],
    packages: list[dict],
    budget: float,
    currency: str = "BRL",
    usd_brl: float = 5.45,
    bucket: float = 50.0,
    must_include: Iterable[str] = (),
    exclude: Iterable[str] = (),
    kev_ids: frozenset[str] | set[str] | None = None,
    compliance_fn=None,
    tools_present: Iterable[str] = (),
    now: datetime | None = None,
    half_point: float = 10.0,
) -> dict:
    """
    Roda a simulação e monta o antes/depois.

    `budget` é sempre interpretado em BRL internamente (a conversão de entrada
    acontece no router). Todo campo monetário da resposta sai nas DUAS moedas,
    para o toggle do frontend ser display puro, sem aritmética no cliente.
    """
    now = now or datetime.now(timezone.utc)
    findings = list(findings)
    must = {str(x) for x in must_include}
    skip = {str(x) for x in exclude}

    candidates = [p for p in packages if p["id"] not in skip]
    forced = [p for p in candidates if p["id"] in must]
    optional = [p for p in candidates if p["id"] not in must]

    forced_cost = sum(p["cost"]["brl"] for p in forced)
    remaining = budget - forced_cost

    if remaining < 0:
        return {
            "error": "must_include_exceeds_budget",
            "detail": (
                f"Os pacotes obrigatórios custam R$ {forced_cost:,.2f}, "
                f"acima do orçamento de R$ {budget:,.2f}."
            ),
            "shortfall": {"brl": round(forced_cost - budget, 2)},
        }

    costs = [p["cost"]["brl"] for p in optional]
    values = [p["risk_points"] for p in optional]

    chosen_idx, dp_value = knapsack(costs, values, remaining, bucket)
    greedy_idx, greedy_value = greedy(costs, values, remaining)

    selected = forced + [optional[i] for i in chosen_idx]
    selected_ids = {p["id"] for p in selected}

    # ── O "depois" ────────────────────────────────────────────────────────────
    # Calculado pelo MESMO caminho do "agora": remove os findings resolvidos e
    # roda compute_posture de novo. Sem bookkeeping de delta, sem chance do
    # "depois" discordar do que o snapshot reportaria quando o trabalho acabar.
    resolved_ids = {fid for p in selected for fid in p["finding_ids"]}
    residual = [f for f in findings if f.get("id") not in resolved_ids]

    before = compute_posture(findings, kev_ids, now, half_point)
    after = compute_posture(residual, kev_ids, now, half_point)

    before_comp = after_comp = None
    if compliance_fn is not None:
        before_comp = compliance_fn(findings, tools_present, kev_ids, now)
        after_comp = compliance_fn(residual, tools_present, kev_ids, now)

    spent_brl = round(sum(p["cost"]["brl"] for p in selected), 2)
    leftover_brl = round(budget - spent_brl, 2)

    # Corte de eficiência: o menos eficiente entre os escolhidos.
    cutoff = min((p["efficiency_per_1k"] for p in selected), default=0.0)

    excluded = []
    for p in candidates:
        if p["id"] in selected_ids:
            continue
        if p["id"] in skip:
            reason, expl = "user_excluded", "Excluído explicitamente na requisição."
        elif p["risk_points"] <= 0:
            reason, expl = "no_risk_reduction", "Não reduz exposição (severidade INFO)."
        elif p["cost"]["brl"] > budget:
            reason, expl = "over_budget", (
                f"Custa R$ {p['cost']['brl']:,.2f}, acima do orçamento total."
            )
        else:
            reason, expl = "lower_efficiency", (
                "Cabe no orçamento, mas nenhuma combinação que o inclua supera o conjunto escolhido."
            )
        excluded.append({
            "package_id": p["id"], "title": p["title"],
            "cost": p["cost"], "risk_points": p["risk_points"],
            "efficiency_per_1k": p["efficiency_per_1k"],
            "reason": reason, "explanation": expl,
            "selection_cutoff_efficiency": round(cutoff, 2),
        })

    # Próximo melhor se o orçamento aumentasse.
    affordable_next = sorted(
        (e for e in excluded if e["reason"] in ("lower_efficiency", "over_budget")),
        key=lambda e: -e["efficiency_per_1k"],
    )
    next_best = None
    if affordable_next:
        nb = affordable_next[0]
        next_best = {
            "package_id": nb["package_id"], "title": nb["title"],
            "cost": nb["cost"], "risk_points": nb["risk_points"],
            "additional_budget_needed": {
                "brl": round(max(0.0, nb["cost"]["brl"] - leftover_brl), 2)
            },
        }

    def money(brl: float) -> dict:
        return {"brl": round(brl, 2), "usd": round(brl / usd_brl, 2) if usd_brl else 0.0}

    # Enriquece os selecionados com contribuição e controles impactados.
    total_points = sum(p["risk_points"] for p in selected) or 1.0
    selected_out = []
    for rank, p in enumerate(sorted(selected, key=lambda x: -x["risk_points"]), 1):
        item = dict(p)
        item["rank"] = rank
        item["score_contribution_pct"] = round(100.0 * p["risk_points"] / total_points, 1)
        item["forced"] = p["id"] in must
        selected_out.append(item)

    dp_adv = round(100.0 * (dp_value - greedy_value) / greedy_value, 1) if greedy_value > 0 else 0.0

    return {
        "budget": {
            "amount": round(budget, 2), "currency": currency,
            **money(budget), "fx_rate": usd_brl,
        },
        "before": {
            "risk_score": before["risk_score"], "risk_level": before["risk_level"],
            "exposure_R": before["exposure_R"],
            "critical_equivalents": before["critical_equivalents"],
            "open_findings": before["open_findings"],
            "findings_by_severity": before["findings_by_severity"],
            "compliance": {
                "overall": before_comp["overall_compliance"] if before_comp else None,
                "by_framework": {
                    k: v["compliance_percentage"] for k, v in before_comp["frameworks"].items()
                } if before_comp else None,
            },
        },
        "after": {
            "risk_score": after["risk_score"], "risk_level": after["risk_level"],
            "exposure_R": after["exposure_R"],
            "critical_equivalents": after["critical_equivalents"],
            "open_findings": after["open_findings"],
            "findings_by_severity": after["findings_by_severity"],
            "floor_applied": after["floor_applied"], "floor_reason": after["floor_reason"],
            "compliance": {
                "overall": after_comp["overall_compliance"] if after_comp else None,
                "by_framework": {
                    k: v["compliance_percentage"] for k, v in after_comp["frameworks"].items()
                } if after_comp else None,
            },
        },
        "delta": {
            "risk_score": round(after["risk_score"] - before["risk_score"], 1),
            "exposure_removed": round(before["exposure_R"] - after["exposure_R"], 2),
            "findings_resolved": len(resolved_ids),
            "compliance_overall": (
                round(after_comp["overall_compliance"] - before_comp["overall_compliance"], 1)
                if before_comp and after_comp else None
            ),
        },
        "selected": selected_out,
        "excluded": sorted(excluded, key=lambda e: -e["efficiency_per_1k"]),
        "spent": money(spent_brl),
        "leftover": money(leftover_brl),
        "leftover_note": (
            f"Backlog completo coberto. Sobra R$ {leftover_brl:,.2f}."
            if not [e for e in excluded if e["reason"] == "lower_efficiency"]
            else f"Sobra R$ {leftover_brl:,.2f} — insuficiente para o próximo pacote."
        ),
        "next_best_if_budget_increased": next_best,
        "optimizer": {
            "method": "0/1_knapsack_dp",
            "optimality": "exact",
            "bucket_size": bucket,
            "packages_considered": len(candidates),
            "packages_forced": len(forced),
            "dp_risk_points": round(dp_value, 2),
            "greedy_baseline_risk_points": round(greedy_value, 2),
            "dp_advantage_pct": dp_adv,
            "note": (
                "Otimização feita no espaço de exposição R, que é aditivo por construção. "
                "A conversão para o score 0-100 (não-linear) é aplicada uma única vez ao "
                "R residual — é isso que torna o problema bem-posto."
            ),
        },
        "disclaimer": (
            "Estimativa de esforço de engenharia. Não é orçamento, cotação nem "
            "compromisso contratual."
        ),
        "calculated_at": now.isoformat(),
    }
