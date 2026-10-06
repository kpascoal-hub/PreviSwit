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
PreviSwit AI-ASPM — core.posture.taxonomy
==========================================
Famílias de controle, classificador determinístico e capacidade das ferramentas.

A CHAVE DE JUNÇÃO
-----------------
Mapear cada regra de cada ferramenta direto para 7 frameworks daria 7xN
entradas impossíveis de manter. Em vez disso:

    finding  ->  exatamente UMA família  ->  N controles de framework

A família é escolhida por REGRAS ORDENADAS, primeiro match vence, e o
`rule_id` da regra que casou volta na resposta da API. Toda afirmação de
conformidade é auditável — nada de caixa-preta.

PRINCÍPIO DE DESEMPATE
----------------------
A família reflete **o caminho de remediação**, não a natureza acadêmica do bug.
`PyYAML CVE-2020-1747` é tecnicamente desserialização insegura, mas classifica
como VULN_COMPONENTS porque se corrige subindo a versão, não reescrevendo
código. Como a família dirige o empacotamento e o custo no simulador, ela tem
que responder "que trabalho isso dá?".
"""
from __future__ import annotations

from typing import Iterable

__all__ = [
    "Family",
    "FAMILY_LABELS",
    "TOOL_CAPABILITIES",
    "classify",
    "classify_all",
    "in_scope_families",
    "tools_for_family",
]


class Family:
    """Famílias de controle. String simples — serializa direto para JSON."""

    SECRETS_MGMT = "SECRETS_MGMT"
    VULN_COMPONENTS = "VULN_COMPONENTS"
    CRYPTO_FAILURES = "CRYPTO_FAILURES"
    ACCESS_CONTROL = "ACCESS_CONTROL"
    INJECTION = "INJECTION"
    SEC_MISCONFIG = "SEC_MISCONFIG"
    SUPPLY_CHAIN_INTEGRITY = "SUPPLY_CHAIN_INTEGRITY"
    LOGGING_MONITORING = "LOGGING_MONITORING"
    DATA_PROTECTION = "DATA_PROTECTION"
    NETWORK_EXPOSURE = "NETWORK_EXPOSURE"
    AUTHN_FAILURES = "AUTHN_FAILURES"
    INSECURE_DESIGN = "INSECURE_DESIGN"

    ALL = (
        SECRETS_MGMT, VULN_COMPONENTS, CRYPTO_FAILURES, ACCESS_CONTROL,
        INJECTION, SEC_MISCONFIG, SUPPLY_CHAIN_INTEGRITY, LOGGING_MONITORING,
        DATA_PROTECTION, NETWORK_EXPOSURE, AUTHN_FAILURES, INSECURE_DESIGN,
    )


FAMILY_LABELS: dict[str, str] = {
    Family.SECRETS_MGMT: "Gestão de Segredos",
    Family.VULN_COMPONENTS: "Componentes Vulneráveis",
    Family.CRYPTO_FAILURES: "Falhas Criptográficas",
    Family.ACCESS_CONTROL: "Controle de Acesso",
    Family.INJECTION: "Injeção",
    Family.SEC_MISCONFIG: "Configuração Insegura",
    Family.SUPPLY_CHAIN_INTEGRITY: "Integridade da Cadeia de Suprimentos",
    Family.LOGGING_MONITORING: "Registro e Monitoramento",
    Family.DATA_PROTECTION: "Proteção de Dados Pessoais",
    Family.NETWORK_EXPOSURE: "Exposição de Rede",
    Family.AUTHN_FAILURES: "Falhas de Autenticação",
    Family.INSECURE_DESIGN: "Design Inseguro",
}


# ── Capacidade das ferramentas ────────────────────────────────────────────────
#
# REGRA DA ASSIMETRIA — o mecanismo central de honestidade do produto:
#
#   Uma ferramenta com capacidade SECUNDÁRIA numa família pode provar que um
#   controle FALHA, mas nunca que ele PASSA.
#
# Findings de capacidade secundária causam dano normalmente; eles simplesmente
# nunca trazem um controle para dentro do escopo avaliável.
#
# Sem isso, `A.8.28 Secure coding` (família INJECTION) pontuaria 100% num
# ambiente onde o Semgrep nunca rodou — não porque o código é seguro, mas
# porque ninguém olhou. Isso seria mentira.
TOOL_CAPABILITIES: dict[str, dict[str, frozenset[str]]] = {
    "trivy": {
        "primary": frozenset({Family.VULN_COMPONENTS}),
        "secondary": frozenset({Family.SEC_MISCONFIG}),
    },
    "checkov": {
        "primary": frozenset({
            Family.SEC_MISCONFIG,
            Family.SECRETS_MGMT,
            Family.SUPPLY_CHAIN_INTEGRITY,
        }),
        "secondary": frozenset({
            Family.ACCESS_CONTROL,
            Family.CRYPTO_FAILURES,
            Family.NETWORK_EXPOSURE,
            Family.LOGGING_MONITORING,
        }),
    },
    "gitleaks": {
        "primary": frozenset({Family.SECRETS_MGMT}),
        "secondary": frozenset({Family.DATA_PROTECTION}),
    },
    "semgrep": {
        "primary": frozenset({
            Family.INJECTION,
            Family.CRYPTO_FAILURES,
            Family.AUTHN_FAILURES,
            Family.ACCESS_CONTROL,
            Family.INSECURE_DESIGN,
        }),
        "secondary": frozenset({
            Family.LOGGING_MONITORING,
            Family.SECRETS_MGMT,
            Family.DATA_PROTECTION,
        }),
    },
    "nuclei": {
        "primary": frozenset({Family.NETWORK_EXPOSURE, Family.SEC_MISCONFIG}),
        "secondary": frozenset({Family.INJECTION}),
    },
    "nmap": {
        "primary": frozenset({Family.NETWORK_EXPOSURE}),
        "secondary": frozenset(),
    },
    "gobuster": {
        "primary": frozenset(),
        "secondary": frozenset({Family.NETWORK_EXPOSURE, Family.ACCESS_CONTROL}),
    },
    "zap": {
        "primary": frozenset({
            Family.INJECTION,
            Family.AUTHN_FAILURES,
            Family.ACCESS_CONTROL,
            Family.NETWORK_EXPOSURE,
        }),
        "secondary": frozenset({Family.SEC_MISCONFIG}),
    },
}


def in_scope_families(tools_present: Iterable[str]) -> frozenset[str]:
    """União das capacidades PRIMÁRIAS das ferramentas presentes."""
    out: set[str] = set()
    for t in tools_present:
        cap = TOOL_CAPABILITIES.get(str(t).strip().lower())
        if cap:
            out |= cap["primary"]
    return frozenset(out)


def tools_for_family(family: str) -> list[str]:
    """Ferramentas que provam esta família (capacidade primária). Alimenta `coverage_gaps`."""
    return sorted(
        tool for tool, cap in TOOL_CAPABILITIES.items()
        if family in cap["primary"]
    )


# ── Tabela de palavras-chave do Semgrep ───────────────────────────────────────
#
# Rule ids do Semgrep têm forma `python.flask.security.injection.tainted-sql-string`.
# Ordem importa: o primeiro substring que casar vence.
SEMGREP_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("hardcoded", Family.SECRETS_MGMT),
    ("secret", Family.SECRETS_MGMT),
    ("api-key", Family.SECRETS_MGMT),
    ("credential", Family.SECRETS_MGMT),

    ("sql-injection", Family.INJECTION),
    ("tainted-sql", Family.INJECTION),
    ("sqli", Family.INJECTION),
    ("command-injection", Family.INJECTION),
    ("os-command", Family.INJECTION),
    ("shell-injection", Family.INJECTION),
    ("code-injection", Family.INJECTION),
    ("template-injection", Family.INJECTION),
    ("cross-site-script", Family.INJECTION),
    ("xss", Family.INJECTION),

    ("ssrf", Family.NETWORK_EXPOSURE),
    ("open-redirect", Family.NETWORK_EXPOSURE),

    ("path-traversal", Family.ACCESS_CONTROL),
    ("zipslip", Family.ACCESS_CONTROL),
    ("csrf", Family.ACCESS_CONTROL),
    ("cors", Family.ACCESS_CONTROL),

    ("deserial", Family.INSECURE_DESIGN),
    ("pickle", Family.INSECURE_DESIGN),
    ("yaml-load", Family.INSECURE_DESIGN),
    ("eval", Family.INSECURE_DESIGN),

    ("insecure-random", Family.CRYPTO_FAILURES),
    ("weak-hash", Family.CRYPTO_FAILURES),
    ("crypto", Family.CRYPTO_FAILURES),
    ("cipher", Family.CRYPTO_FAILURES),
    ("md5", Family.CRYPTO_FAILURES),
    ("sha1", Family.CRYPTO_FAILURES),
    ("verify-false", Family.CRYPTO_FAILURES),
    ("tls", Family.CRYPTO_FAILURES),
    ("ssl", Family.CRYPTO_FAILURES),

    ("jwt", Family.AUTHN_FAILURES),
    ("session", Family.AUTHN_FAILURES),
    ("auth", Family.AUTHN_FAILURES),

    ("audit", Family.LOGGING_MONITORING),
    ("logging", Family.LOGGING_MONITORING),

    ("debug", Family.SEC_MISCONFIG),
    ("insecure-config", Family.SEC_MISCONFIG),
)

# Fallback genérico sobre title + description, para qualquer ferramenta.
GENERIC_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("hardcoded secret", Family.SECRETS_MGMT),
    ("hard-coded", Family.SECRETS_MGMT),
    ("api key", Family.SECRETS_MGMT),
    ("private key", Family.SECRETS_MGMT),
    ("password", Family.SECRETS_MGMT),

    ("sql injection", Family.INJECTION),
    ("command injection", Family.INJECTION),
    ("cross-site scripting", Family.INJECTION),
    ("xss", Family.INJECTION),

    ("encryption", Family.CRYPTO_FAILURES),
    ("unencrypted", Family.CRYPTO_FAILURES),
    ("cryptograph", Family.CRYPTO_FAILURES),
    ("tls", Family.CRYPTO_FAILURES),

    ("authentication", Family.AUTHN_FAILURES),
    ("authorization", Family.ACCESS_CONTROL),
    ("permission", Family.ACCESS_CONTROL),
    ("public access", Family.ACCESS_CONTROL),
    ("publicly accessible", Family.NETWORK_EXPOSURE),
    ("0.0.0.0/0", Family.NETWORK_EXPOSURE),
    ("ingress", Family.NETWORK_EXPOSURE),

    ("logging", Family.LOGGING_MONITORING),
    ("audit", Family.LOGGING_MONITORING),

    ("personal data", Family.DATA_PROTECTION),
    ("dados pessoais", Family.DATA_PROTECTION),
)


def classify(f: dict) -> tuple[str, str]:
    """
    Classifica um finding em `(família, rule_id)`.

    Regras ordenadas, primeiro match vence. O `rule_id` é ecoado na API para
    que cada afirmação de conformidade seja rastreável até a regra que a gerou.
    """
    tool = str(f.get("tool") or "").strip().lower()
    name = str(f.get("name") or "").strip().upper()
    cve = str(f.get("cve_id") or "").strip()
    tags = {str(t).strip().upper() for t in (f.get("tags") or [])}

    # R1 — Gitleaks: por definição, segredo exposto.
    if tool == "gitleaks":
        return Family.SECRETS_MGMT, "tool:gitleaks"

    # R2 — Checkov de segredo. Antes do R3 porque é mais específico.
    if name.startswith("CKV_SECRET_"):
        return Family.SECRETS_MGMT, "ckv:secret"

    # R3 — Trivy com CVE. Dispara ANTES das keywords do Semgrep de propósito:
    # a remediação é subir versão, não reescrever código.
    if tool == "trivy" and cve:
        return Family.VULN_COMPONENTS, "trivy:cve"

    # R4..R8 — Checkov por prefixo do check id.
    if name.startswith("CKV_DOCKER_"):
        return Family.SEC_MISCONFIG, "ckv:docker"
    if name.startswith(("CKV_AWS_", "CKV_AZURE_", "CKV_GCP_", "CKV2_AWS_", "CKV2_AZURE_", "CKV2_GCP_")):
        return Family.SEC_MISCONFIG, "ckv:cloud"
    if name.startswith(("CKV_K8S_", "CKV2_K8S_")):
        return Family.SEC_MISCONFIG, "ckv:k8s"
    if name.startswith(("CKV2_GHA_", "CKV_GHA_", "CKV_GITLABCI_", "CKV_CIRCLECIPIPELINES_")):
        return Family.SUPPLY_CHAIN_INTEGRITY, "ckv:gha"
    if name.startswith(("CKV_", "CKV2_")):
        return Family.SEC_MISCONFIG, "ckv:generic"

    # R9 — Semgrep por keyword no rule id.
    if tool == "semgrep":
        rule = name.lower()
        for kw, fam in SEMGREP_KEYWORDS:
            if kw in rule:
                return fam, f"semgrep:kw:{kw}"

    # R10 — Tags (sinal grosseiro, mas persistido por todos os parsers).
    if "CVE" in tags:
        return Family.VULN_COMPONENTS, "tags:CVE"
    if "SECRET" in tags or "SECRETS" in tags:
        return Family.SECRETS_MGMT, "tags:SECRET"
    if "IAC" in tags:
        return Family.SEC_MISCONFIG, "tags:IAC"

    # R11 — Keyword genérica sobre título + descrição.
    haystack = f"{f.get('title') or ''} {f.get('description') or ''}".lower()
    for kw, fam in GENERIC_KEYWORDS:
        if kw in haystack:
            return fam, f"kw:{kw}"

    # R12 — Fallback.
    return Family.INSECURE_DESIGN, "default"


def classify_all(findings: Iterable[dict]) -> tuple[list[dict], dict[str, int]]:
    """
    Classifica uma lista, anexando `_family` e `_mapped_by` a cada registro.
    Devolve `(findings_enriquecidos, contagem_por_familia)`.
    """
    out: list[dict] = []
    counts: dict[str, int] = {}

    for f in findings:
        fam, rule_id = classify(f)
        rec = dict(f)
        rec["_family"] = fam
        rec["_mapped_by"] = rule_id
        out.append(rec)
        counts[fam] = counts.get(fam, 0) + 1

    return out, counts
