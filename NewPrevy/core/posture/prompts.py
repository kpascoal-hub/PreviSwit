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
PreviSwit AI-ASPM — core.posture.prompts
=========================================
Construção de prompt aterrado e fallback determinístico.

O CONTRATO ANTI-ALUCINAÇÃO
--------------------------
Todo número entregue ao Gemini vem da computação do servidor, e o bloco exato
de dados entregue volta na resposta como `grounding`. A UI renderiza
"baseado em: 57 findings, R$ 20.000, ISO 27001 39,2%" ao lado da prosa —
qualquer pessoa consegue conferir se o modelo respeitou os dados.

O FALLBACK DETERMINÍSTICO
-------------------------
Sem chave Gemini ou com o serviço fora, `deterministic_summary()` renderiza
os MESMOS dados por template. O painel nunca fica vazio e nunca fabrica:
é dado real computado, só que não redigido por LLM.
"""
from __future__ import annotations

__all__ = ["SYSTEM_INSTRUCTION", "build_grounding", "build_prompt", "deterministic_summary"]


SYSTEM_INSTRUCTION = (
    "Você é um CISO consultivo apresentando postura de segurança para a diretoria "
    "de uma empresa brasileira.\n\n"
    "REGRAS ABSOLUTAS:\n"
    "1. Use EXCLUSIVAMENTE os números do bloco DADOS abaixo.\n"
    "2. É PROIBIDO inventar percentuais, valores monetários, CVEs, nomes de pacotes, "
    "controles de framework ou datas que não estejam no bloco DADOS.\n"
    "3. Se uma informação não estiver presente, escreva 'não medido' — nunca estime.\n"
    "4. Não cite notícias, incidentes de mercado ou estatísticas do setor: você não "
    "tem dados atualizados sobre isso.\n"
    "5. Responda em português brasileiro, direto e sem jargão desnecessário.\n"
    "6. Percentuais de conformidade referem-se APENAS aos controles observáveis pelas "
    "ferramentas presentes — nunca os apresente como auditoria ou certificação."
)

_FOCUS_BRIEF = {
    "business": (
        "Escreva para um diretor não-técnico. Foque em: o que está em risco para o "
        "negócio, o que comprar primeiro e por quê, e qual o retorno esperado. "
        "Máximo 250 palavras, em 3 blocos curtos."
    ),
    "technical": (
        "Escreva para um tech lead. Foque em: quais pacotes/arquivos corrigir, em que "
        "ordem, e qual o impacto técnico de cada um. Máximo 300 palavras."
    ),
    "board": (
        "Escreva para o conselho. Foque em: exposição regulatória (LGPD), tendência do "
        "risco e a decisão de investimento que está sendo pedida. Máximo 200 palavras, "
        "sem jargão técnico."
    ),
}


def build_grounding(
    snapshot: dict,
    compliance: dict | None = None,
    packages: list[dict] | None = None,
    simulation: dict | None = None,
    kev_matches: list[str] | None = None,
) -> dict:
    """Extrai o bloco de dados exato que será entregue ao modelo e ecoado na API."""
    g: dict = {
        "risk_score": snapshot.get("risk_score"),
        "risk_level": snapshot.get("risk_level"),
        "score_convention": "0 = melhor, 100 = pior",
        "open_findings": snapshot.get("open_findings"),
        "findings_by_severity": snapshot.get("findings_by_severity"),
        "critical_equivalents": snapshot.get("critical_equivalents"),
        "kev_available": snapshot.get("kev_available"),
        "top_drivers": [
            {"title": d.get("title"), "severity": d.get("severity"),
             "package": d.get("package"), "cve_id": d.get("cve_id")}
            for d in (snapshot.get("top_drivers") or [])[:5]
        ],
    }

    if compliance:
        g["compliance_overall"] = compliance.get("overall_compliance")
        g["compliance_by_framework"] = {
            k: {
                "percentage": v["compliance_percentage"],
                "in_scope_controls": v["in_scope_controls"],
                "catalog_total": v["catalog_total_controls"],
            }
            for k, v in compliance.get("frameworks", {}).items()
        }
        g["tools_present"] = compliance.get("evidence", {}).get("tools_present")
        g["coverage_gaps"] = [
            {"framework": k, "control": gap["control"], "enable_tools": gap["enable_tools"]}
            for k, v in compliance.get("frameworks", {}).items()
            for gap in v.get("coverage_gaps", [])[:2]
        ][:8]

    if packages:
        g["top_packages"] = [
            {"title": p["title"], "cost_brl": p["cost"]["brl"],
             "findings_resolved": p["findings_count"],
             "efficiency_per_1k": p["efficiency_per_1k"]}
            for p in packages[:6]
        ]

    if simulation and not simulation.get("error"):
        g["simulation"] = {
            "budget_brl": simulation["budget"]["brl"],
            "spent_brl": simulation["spent"]["brl"],
            "leftover_brl": simulation["leftover"]["brl"],
            "score_before": simulation["before"]["risk_score"],
            "score_after": simulation["after"]["risk_score"],
            "findings_resolved": simulation["delta"]["findings_resolved"],
            "compliance_before": simulation["before"]["compliance"]["overall"],
            "compliance_after": simulation["after"]["compliance"]["overall"],
            "selected": [
                {"title": s["title"], "cost_brl": s["cost"]["brl"],
                 "findings": s["findings_count"]}
                for s in simulation.get("selected", [])[:8]
            ],
        }

    if kev_matches:
        g["kev_matches"] = kev_matches[:10]
        g["kev_match_count"] = len(kev_matches)

    return g


def build_prompt(grounding: dict, focus: str = "business") -> str:
    """Monta o prompt final. Todo número vem do `grounding`."""
    import json
    brief = _FOCUS_BRIEF.get(focus, _FOCUS_BRIEF["business"])
    return (
        f"{brief}\n\n"
        "===== DADOS (única fonte permitida) =====\n"
        f"{json.dumps(grounding, ensure_ascii=False, indent=2, default=str)}\n"
        "===== FIM DOS DADOS =====\n\n"
        "Produza a análise usando somente os números acima."
    )


def deterministic_summary(grounding: dict) -> str:
    """
    Resumo por template, sem LLM. É o que aparece quando não há chave Gemini
    ou o serviço está fora — dado real, apenas não redigido por modelo.
    """
    L: list[str] = []
    score = grounding.get("risk_score")
    level = grounding.get("risk_level")
    n = grounding.get("open_findings")
    sev = grounding.get("findings_by_severity") or {}

    L.append(f"**Postura atual: risco {score} ({level})** — {n} findings abertos.")
    parts = [f"{v} {k.lower()}" for k, v in sev.items() if v]
    if parts:
        L.append(f"Distribuição: {', '.join(parts)}.")

    if grounding.get("kev_match_count"):
        L.append(
            f"\n**Alerta:** {grounding['kev_match_count']} das suas CVEs constam no catálogo "
            f"KEV da CISA — exploração confirmada em campo."
        )

    comp = grounding.get("compliance_by_framework") or {}
    if comp:
        L.append("\n**Conformidade** (apenas controles observáveis pelas ferramentas presentes):")
        for k, v in sorted(comp.items(), key=lambda kv: -kv[1]["percentage"]):
            L.append(
                f"- {k.replace('_', ' ')}: {v['percentage']}% "
                f"sobre {v['in_scope_controls']} de {v['catalog_total']} controles"
            )

    sim = grounding.get("simulation")
    if sim:
        L.append(
            f"\n**Simulação de investimento** — com R$ {sim['budget_brl']:,.2f}, "
            f"gastando R$ {sim['spent_brl']:,.2f}, o risco cai de {sim['score_before']} "
            f"para {sim['score_after']} e {sim['findings_resolved']} findings são resolvidos."
        )
        if sim.get("selected"):
            L.append("\nPrioridades:")
            for i, s in enumerate(sim["selected"][:5], 1):
                L.append(f"{i}. {s['title']} — R$ {s['cost_brl']:,.2f} ({s['findings']} findings)")

    gaps = grounding.get("coverage_gaps") or []
    if gaps:
        tools = sorted({t for g in gaps for t in g.get("enable_tools", [])})
        L.append(
            f"\n**Ampliar cobertura:** habilitar {', '.join(tools)} colocaria mais controles "
            f"em escopo de avaliação."
        )

    L.append(
        "\n_Resumo gerado deterministicamente a partir dos dados computados "
        "(chave Gemini ausente ou serviço indisponível)._"
    )
    return "\n".join(L)
