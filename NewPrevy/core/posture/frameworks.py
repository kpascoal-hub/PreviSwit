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
PreviSwit AI-ASPM — core.posture.frameworks
============================================
Catálogos dos 7 frameworks e cálculo de conformidade.

O PROBLEMA DA HONESTIDADE
-------------------------
`A.8.28 Secure coding` da ISO 27001 mapeia na família INJECTION. Se o Semgrep
nunca rodou, não temos nenhum finding de injeção — e pontuar esse controle
como 100% seria mentira: ninguém olhou.

O mecanismo é a REGRA DA ASSIMETRIA (ver `taxonomy.TOOL_CAPABILITIES`):
uma ferramenta secundária pode provar que um controle FALHA, nunca que PASSA.
Um controle só entra em escopo se alguma ferramenta com capacidade PRIMÁRIA
naquela família estiver presente.

Consequência: a API reporta TRÊS números de cobertura, nunca um só.
"ISO 27001: 38,8%" sem "sobre 6 dos 93 controles" é propaganda enganosa.

O campo `granularity` existe porque comparar 75% de cobertura do PCI (12
requisitos de alto nível) com 9,4% do NIST CSF (106 subcategorias) sem dizer
que as unidades são diferentes seria enganoso na outra direção.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from core.posture.scoring import W_SEV, control_health
from core.posture.normalize import age_multiplier, exploit_multiplier, is_open, severity_of
from core.posture.taxonomy import Family, in_scope_families, tools_for_family

__all__ = ["Control", "FRAMEWORKS", "compute_compliance"]

F = Family


@dataclass(frozen=True)
class Control:
    """Um controle avaliável. `importance` 1..3 pondera a média do framework."""
    id: str
    title: str
    families: tuple[str, ...]
    importance: int = 2
    note: str = ""


# ── Os 7 catálogos ────────────────────────────────────────────────────────────
#
# `technical_subset` = controles avaliáveis por ferramentas de código.
# `catalog_total_controls` = tamanho REAL do framework completo.
# A diferença entre os dois é a parte honesta.

FRAMEWORKS: dict[str, dict] = {

    "OWASP_TOP_10_2021": {
        "name": "OWASP Top 10 2021",
        "version": "2021",
        "authority": "OWASP Foundation",
        "url": "https://owasp.org/Top10/",
        "catalog_total_controls": 10,
        "granularity": "category",
        "granularity_label": "categoria",
        "scope_note": (
            "O OWASP Top 10 é uma lista de conscientização sobre categorias de risco "
            "em aplicações web, não um padrão certificável. Cobertura alta aqui é "
            "esperada: as 10 categorias são justamente o que ferramentas SAST/DAST medem."
        ),
        "technical_subset": (
            Control("A01", "Broken Access Control", (F.ACCESS_CONTROL,), 3),
            Control("A02", "Cryptographic Failures", (F.CRYPTO_FAILURES, F.SECRETS_MGMT), 3),
            Control("A03", "Injection", (F.INJECTION,), 3),
            Control("A04", "Insecure Design", (F.INSECURE_DESIGN,), 2),
            Control("A05", "Security Misconfiguration", (F.SEC_MISCONFIG,), 3),
            Control("A06", "Vulnerable and Outdated Components", (F.VULN_COMPONENTS,), 3),
            Control("A07", "Identification and Authentication Failures", (F.AUTHN_FAILURES,), 3),
            Control("A08", "Software and Data Integrity Failures", (F.SUPPLY_CHAIN_INTEGRITY,), 2),
            Control("A09", "Security Logging and Monitoring Failures", (F.LOGGING_MONITORING,), 2),
            Control("A10", "Server-Side Request Forgery (SSRF)", (F.NETWORK_EXPOSURE,), 2),
        ),
    },

    "ISO_27001_2022": {
        "name": "ISO/IEC 27001:2022 — Anexo A",
        "version": "2022",
        "authority": "ISO/IEC",
        "url": "https://www.iso.org/standard/27001",
        "catalog_total_controls": 93,
        "granularity": "control",
        "granularity_label": "controle",
        "scope_note": (
            "O Anexo A tem 93 controles em 4 temas (organizacional, pessoas, físico, "
            "tecnológico). Apenas o tema tecnológico é parcialmente observável por "
            "análise de código. Este percentual NÃO constitui auditoria nem certificação."
        ),
        "technical_subset": (
            Control("A.5.17", "Authentication information", (F.SECRETS_MGMT,), 3),
            Control("A.8.2", "Privileged access rights", (F.ACCESS_CONTROL,), 2),
            Control("A.8.3", "Information access restriction", (F.ACCESS_CONTROL,), 2),
            Control("A.8.4", "Access to source code", (F.SECRETS_MGMT, F.SUPPLY_CHAIN_INTEGRITY), 2),
            Control("A.8.8", "Management of technical vulnerabilities", (F.VULN_COMPONENTS,), 3),
            Control("A.8.9", "Configuration management", (F.SEC_MISCONFIG,), 3),
            Control("A.8.15", "Logging", (F.LOGGING_MONITORING,), 2),
            Control("A.8.20", "Networks security", (F.NETWORK_EXPOSURE,), 2),
            Control("A.8.24", "Use of cryptography", (F.CRYPTO_FAILURES,), 3),
            Control("A.8.25", "Secure development life cycle", (F.SUPPLY_CHAIN_INTEGRITY,), 2),
            Control("A.8.26", "Application security requirements", (F.INSECURE_DESIGN, F.AUTHN_FAILURES), 2),
            Control("A.8.28", "Secure coding", (F.INJECTION, F.INSECURE_DESIGN), 3),
            Control("A.8.31", "Separation of development, test and production", (F.SEC_MISCONFIG,), 1),
        ),
    },

    "SOC2_TSC_2017": {
        "name": "SOC 2 — Trust Services Criteria",
        "version": "2017 (rev. 2022)",
        "authority": "AICPA",
        "url": "https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services",
        "catalog_total_controls": 33,
        "granularity": "criterion",
        "granularity_label": "critério",
        "scope_note": (
            "SOC 2 avalia desenho e efetividade operacional de controles ao longo de um "
            "período, por auditor independente. Evidência automatizada de código é insumo "
            "para a auditoria, nunca substituto dela."
        ),
        "technical_subset": (
            Control("CC6.1", "Logical access security software and infrastructure", (F.ACCESS_CONTROL, F.SECRETS_MGMT), 3),
            Control("CC6.2", "Registration and authorization of users", (F.AUTHN_FAILURES,), 2),
            Control("CC6.3", "Role-based access and least privilege", (F.ACCESS_CONTROL,), 3),
            Control("CC6.6", "Protection against threats from outside the system", (F.NETWORK_EXPOSURE, F.SEC_MISCONFIG), 3),
            Control("CC6.7", "Restriction of information transmission", (F.CRYPTO_FAILURES, F.DATA_PROTECTION), 3),
            Control("CC6.8", "Prevention and detection of unauthorized software", (F.SUPPLY_CHAIN_INTEGRITY,), 2),
            Control("CC7.1", "Detection of configuration changes and vulnerabilities", (F.VULN_COMPONENTS, F.SEC_MISCONFIG), 3),
            Control("CC7.2", "Monitoring of anomalies and security events", (F.LOGGING_MONITORING,), 2),
            Control("CC8.1", "Change management", (F.SUPPLY_CHAIN_INTEGRITY,), 2),
        ),
    },

    "NIST_CSF_2_0": {
        "name": "NIST Cybersecurity Framework 2.0",
        "version": "2.0 (2024)",
        "authority": "NIST",
        "url": "https://www.nist.gov/cyberframework",
        "catalog_total_controls": 106,
        "granularity": "subcategory",
        "granularity_label": "subcategoria",
        "scope_note": (
            "O CSF 2.0 tem 6 funções (GV, ID, PR, DE, RS, RC) e 106 subcategorias. "
            "Governar, Responder e Recuperar são majoritariamente processuais e não "
            "observáveis por análise estática."
        ),
        "technical_subset": (
            Control("ID.RA-01", "Vulnerabilities in assets are identified and recorded", (F.VULN_COMPONENTS,), 3),
            Control("ID.RA-09", "Authenticity and integrity of software is assessed", (F.SUPPLY_CHAIN_INTEGRITY,), 2),
            Control("PR.AA-01", "Identities and credentials are managed", (F.SECRETS_MGMT, F.AUTHN_FAILURES), 3),
            Control("PR.AA-05", "Access permissions enforce least privilege", (F.ACCESS_CONTROL,), 3),
            Control("PR.DS-01", "Confidentiality and integrity of data at rest", (F.CRYPTO_FAILURES, F.DATA_PROTECTION), 3),
            Control("PR.DS-02", "Confidentiality and integrity of data in transit", (F.CRYPTO_FAILURES,), 3),
            Control("PR.PS-01", "Configuration management practices are established", (F.SEC_MISCONFIG,), 3),
            Control("PR.PS-06", "Secure software development practices are integrated", (F.INJECTION, F.INSECURE_DESIGN), 3),
            Control("PR.IR-01", "Networks and environments are protected", (F.NETWORK_EXPOSURE,), 2),
            Control("DE.CM-09", "Computing hardware and software are monitored", (F.LOGGING_MONITORING,), 2),
        ),
    },

    "PCI_DSS_4_0": {
        "name": "PCI DSS v4.0",
        "version": "4.0",
        "authority": "PCI Security Standards Council",
        "url": "https://www.pcisecuritystandards.org/",
        "catalog_total_controls": 12,
        "granularity": "requirement",
        "granularity_label": "requisito",
        "scope_note": (
            "Avaliado no nível dos 12 REQUISITOS de alto nível, não das ~300 "
            "sub-requisições. Cobertura alta aqui não é equivalente a cobertura alta "
            "num framework medido em controle individual. Aplicável apenas se houver "
            "dado de portador de cartão no escopo."
        ),
        "technical_subset": (
            Control("1", "Install and maintain network security controls", (F.NETWORK_EXPOSURE,), 3),
            Control("2", "Apply secure configurations to all system components", (F.SEC_MISCONFIG,), 3),
            Control("3", "Protect stored account data", (F.CRYPTO_FAILURES, F.DATA_PROTECTION), 3),
            Control("4", "Protect cardholder data with strong cryptography during transmission", (F.CRYPTO_FAILURES,), 3),
            Control("6", "Develop and maintain secure systems and software", (F.VULN_COMPONENTS, F.INJECTION, F.INSECURE_DESIGN), 3),
            Control("7", "Restrict access by business need to know", (F.ACCESS_CONTROL,), 3),
            Control("8", "Identify users and authenticate access", (F.AUTHN_FAILURES, F.SECRETS_MGMT), 3),
            Control("10", "Log and monitor all access to system components", (F.LOGGING_MONITORING,), 2),
            Control("11", "Test security of systems and networks regularly", (F.VULN_COMPONENTS, F.NETWORK_EXPOSURE), 2),
        ),
    },

    "CIS_CONTROLS_V8": {
        "name": "CIS Critical Security Controls v8",
        "version": "8",
        "authority": "Center for Internet Security",
        "url": "https://www.cisecurity.org/controls/v8",
        "catalog_total_controls": 18,
        "granularity": "control",
        "granularity_label": "controle",
        "scope_note": (
            "Avaliado no nível dos 18 controles, não das 153 salvaguardas. "
            "Controles de inventário físico, treinamento e resposta a incidente não "
            "são observáveis por análise de código."
        ),
        "technical_subset": (
            Control("2", "Inventory and Control of Software Assets", (F.VULN_COMPONENTS, F.SUPPLY_CHAIN_INTEGRITY), 2),
            Control("3", "Data Protection", (F.DATA_PROTECTION, F.CRYPTO_FAILURES), 3),
            Control("4", "Secure Configuration of Enterprise Assets and Software", (F.SEC_MISCONFIG,), 3),
            Control("5", "Account Management", (F.SECRETS_MGMT, F.AUTHN_FAILURES), 3),
            Control("6", "Access Control Management", (F.ACCESS_CONTROL,), 3),
            Control("7", "Continuous Vulnerability Management", (F.VULN_COMPONENTS,), 3),
            Control("8", "Audit Log Management", (F.LOGGING_MONITORING,), 2),
            Control("12", "Network Infrastructure Management", (F.NETWORK_EXPOSURE,), 2),
            Control("16", "Application Software Security", (F.INJECTION, F.INSECURE_DESIGN), 3),
        ),
    },

    "LGPD": {
        "name": "LGPD — Lei nº 13.709/2018",
        "version": "Lei nº 13.709/2018",
        "authority": "ANPD — Autoridade Nacional de Proteção de Dados",
        "url": "https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm",
        "catalog_total_controls": 65,
        "granularity": "article",
        "granularity_label": "artigo",
        "scope_note": (
            "A LGPD é majoritariamente jurídica e procedimental: base legal, direitos do "
            "titular, DPO, RIPD, contratos de operador. Apenas os artigos de segurança "
            "técnica (Art. 46-49) têm evidência observável em código. Conformidade legal "
            "com a LGPD NÃO se demonstra por scanner."
        ),
        "technical_subset": (
            Control("Art. 46", "Medidas de segurança técnicas e administrativas",
                    (F.SECRETS_MGMT, F.CRYPTO_FAILURES, F.ACCESS_CONTROL, F.DATA_PROTECTION), 3),
            Control("Art. 47", "Obrigação de segurança dos agentes de tratamento",
                    (F.SEC_MISCONFIG, F.VULN_COMPONENTS), 3),
            Control("Art. 48", "Comunicação de incidente de segurança à ANPD",
                    (F.LOGGING_MONITORING,), 3),
            Control("Art. 49", "Sistemas estruturados para atender à segurança",
                    (F.INSECURE_DESIGN, F.SEC_MISCONFIG), 2),
            Control("Art. 6º VII", "Princípio da segurança",
                    (F.CRYPTO_FAILURES, F.NETWORK_EXPOSURE), 2),
            Control("Art. 6º VIII", "Princípio da prevenção",
                    (F.VULN_COMPONENTS, F.INJECTION), 2),
            Control("Art. 50", "Boas práticas e governança",
                    (F.SUPPLY_CHAIN_INTEGRITY,), 1),
        ),
    },
}


def _status_for(pct: float) -> tuple[str, str]:
    """Status técnico + rótulo humano. Nunca diz 'compliant' sem qualificar."""
    if pct >= 90:
        return "compliant", "Evidência forte — não auditado"
    if pct >= 70:
        return "partial", "Evidência parcial — lacunas identificadas"
    if pct >= 40:
        return "partial", "Evidência parcial — não auditado"
    return "non_compliant", "Falhas relevantes detectadas"


def compute_compliance(
    findings: Iterable[dict],
    tools_present: Iterable[str],
    kev_ids: frozenset[str] | set[str] | None = None,
    now: datetime | None = None,
    sla_days: dict[str, int] | None = None,
) -> dict:
    """
    Calcula conformidade por framework a partir de findings JÁ classificados
    (isto é, com `_family` e `_mapped_by` anexados por `taxonomy.classify_all`).

    Fórmula, por controle `c` em escopo:

        D_c = Σ (W_SEV · age_mult · exploit_mult) dos findings abertos das famílias de c
        p_c = (1 + D_c / W_CRIT) ** (-4/3)

        conformidade_% = 100 · Σ(imp_c · p_c) / Σ(imp_c)

    Por que isso e não `100 - n·2` (a fórmula anterior):

    1. Dá exatamente 100% com zero findings; nunca negativo. `100 - n·2` retorna
       0.0 com 64 findings e iria a negativo sem o `max(0, …)` — não é
       percentual de coisa nenhuma.
    2. O dano é POR CONTROLE. Corrigir todas as CVEs não pode mascarar que o
       controle de segredos continua quebrado. Uma fórmula global com fator de
       ajuste fixo (0,9 / 0,85 / 0,875) é estruturalmente incapaz de expressar isso.
    3. Usa o mesmo `W_SEV` do score de risco — conformidade e risco nunca contam
       histórias contraditórias.
    """
    from core.posture.scoring import SLA_DAYS as _SLA
    sla = sla_days or _SLA
    now = now or datetime.now(timezone.utc)
    tools = sorted({str(t).strip().lower() for t in tools_present if t})
    scope = in_scope_families(tools)

    # Dano acumulado por família.
    family_damage: dict[str, float] = {}
    family_findings: dict[str, list[dict]] = {}

    for f in findings:
        if not is_open(f):
            continue
        fam = f.get("_family") or Family.INSECURE_DESIGN
        pts = (
            W_SEV.get(severity_of(f), 1.0)
            * age_multiplier(f, sla, now)
            * exploit_multiplier(f, kev_ids)
        )
        family_damage[fam] = family_damage.get(fam, 0.0) + pts
        family_findings.setdefault(fam, []).append(f)

    out_frameworks: dict[str, dict] = {}
    overall_num = 0.0
    overall_den = 0

    for fw_key, fw in FRAMEWORKS.items():
        subset: tuple[Control, ...] = fw["technical_subset"]
        controls_out: list[dict] = []
        gaps: list[dict] = []
        num = 0.0
        den = 0

        for c in subset:
            # Um controle está em escopo se ALGUMA de suas famílias é coberta
            # por capacidade primária de alguma ferramenta presente.
            covered = [fam for fam in c.families if fam in scope]
            in_scope = bool(covered)

            damage = sum(family_damage.get(fam, 0.0) for fam in c.families)
            open_n = sum(len(family_findings.get(fam, [])) for fam in c.families)

            if in_scope:
                health = control_health(damage)
                num += c.importance * health
                den += c.importance
            else:
                health = None
                # Só vira "gap" se nenhuma ferramenta presente cobre — e existe
                # ferramenta que cobriria.
                enablers = sorted({t for fam in c.families for t in tools_for_family(fam)})
                missing = [t for t in enablers if t not in tools]
                if missing:
                    gaps.append({
                        "control": c.id,
                        "title": c.title,
                        "importance": c.importance,
                        "blocked_by": "no_tool",
                        "families": list(c.families),
                        "enable_tools": missing,
                        "ws_action": _WS_ACTION.get(missing[0]),
                    })

            controls_out.append({
                "id": c.id,
                "title": c.title,
                "importance": c.importance,
                "families": list(c.families),
                "in_scope": in_scope,
                "covered_by_families": covered,
                "health": round(health, 4) if health is not None else None,
                "health_pct": round(health * 100, 1) if health is not None else None,
                "damage": round(damage, 2),
                "open_findings": open_n if in_scope else 0,
                "note": c.note or None,
            })

        in_scope_n = sum(1 for c in controls_out if c["in_scope"])
        pct = round(100.0 * num / den, 1) if den else 0.0
        status, status_label = _status_for(pct) if den else ("not_assessed", "Não avaliado — nenhuma ferramenta cobre este framework")

        total = fw["catalog_total_controls"]
        # Quanto cada gap somaria à cobertura, se a ferramenta fosse habilitada.
        for g in gaps:
            g["would_add_controls"] = sum(
                1 for c in subset
                if any(fam in [gf for gf in g["families"]] for fam in c.families) and
                not any(fam in scope for fam in c.families)
            )
            g["would_raise_coverage_to"] = round((in_scope_n + g["would_add_controls"]) / total, 4)

        out_frameworks[fw_key] = {
            "key": fw_key,
            "name": fw["name"],
            "version": fw["version"],
            "authority": fw["authority"],
            "url": fw["url"],
            "compliance_percentage": pct,
            "status": status,
            "status_label": status_label,
            "catalog_total_controls": total,
            "technical_subset_size": len(subset),
            "in_scope_controls": in_scope_n,
            "coverage_of_catalog": round(in_scope_n / total, 4) if total else 0.0,
            "coverage_of_technical_subset": round(in_scope_n / len(subset), 4) if subset else 0.0,
            "granularity": fw["granularity"],
            "granularity_label": fw["granularity_label"],
            "scope_note": fw["scope_note"],
            "controls": controls_out,
            "coverage_gaps": sorted(gaps, key=lambda g: (-g["importance"], g["control"])),
            "summary_label": (
                f"{pct}% de conformidade sobre {in_scope_n} de {total} "
                f"{fw['granularity_label']}s ({round(100 * in_scope_n / total, 1)}% do catálogo), "
                f"observáveis por {' + '.join(tools) if tools else 'nenhuma ferramenta'}. "
                f"Não constitui auditoria nem certificação."
            ),
        }

        # Agregado ponderado por nº de controles em escopo: um framework com 6
        # controles não pode pesar igual a um com 10.
        if in_scope_n:
            overall_num += pct * in_scope_n
            overall_den += in_scope_n

    return {
        "frameworks": out_frameworks,
        "overall_compliance": round(overall_num / overall_den, 1) if overall_den else 0.0,
        "overall_note": (
            "Indicador agregado, ponderado pelo número de controles em escopo de cada "
            "framework. Os percentuais por framework são os números reais; este é "
            "apenas um resumo de topo."
        ),
        "family_damage": {k: round(v, 2) for k, v in sorted(family_damage.items())},
        "evidence": {
            "tools_present": tools,
            "in_scope_families": sorted(scope),
            "assessment_type": "automated_code_evidence_only",
            "kev_enrichment": kev_ids is not None,
        },
        "disclaimer": (
            "Percentuais calculados APENAS sobre controles observáveis pelas ferramentas "
            "presentes. Não constitui auditoria, certificação ou parecer de conformidade legal."
        ),
        "calculated_at": now.isoformat(),
    }


# Ações de WebSocket que o agente já aceita (ver api/api.py:_AGENT_ACTIONS).
_WS_ACTION = {
    "semgrep": "RUN_SEMGREP",
    "gitleaks": "RUN_GITLEAKS",
    "checkov": "RUN_CHECKOV",
}
