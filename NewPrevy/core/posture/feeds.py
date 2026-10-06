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
PreviSwit AI-ASPM — core.posture.feeds
=======================================
Radar de ameaças (CISA / NVD / KEV) e timeline regulatória.

PRINCÍPIO: OFFLINE-FIRST
------------------------
Todo caminho desta módulo devolve dados utilizáveis. Nenhuma falha de rede
pode derrubar a página. Sem cache e sem rede -> lista vazia com `degraded=true`,
nunca uma exceção.

O KEV NÃO É DECORAÇÃO
---------------------
A lista de Known Exploited Vulnerabilities da CISA alimenta o
`exploit_multiplier` do scoring. É ela que permite dizer "3 das suas CVEs
estão sendo ativamente exploradas" como fato computado — e faz o radar
MUDAR O SCORE em vez de só enfeitar a tela.

Quando o KEV está indisponível, `kev_available=false` é propagado até a API,
e o frontend mostra "enriquecimento KEV indisponível" em vez de reportar
silenciosamente um número diferente.

NADA DE CONTEÚDO GERADO POR IA AQUI
-----------------------------------
O Gemini tem corte de conhecimento e não sabe notícias recentes. Pedir a ele
"liste as últimas notícias" produziria datas e fatos inventados — violando a
regra anti-alucinação do próprio system_instruction do produto. Por isso:
fontes autoritativas via HTTP, e uma timeline curada com `verified_at`.
"""
from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from core.posture.store import FEED_CACHE_FILE, load_json, save_json

__all__ = ["fetch_all", "get_kev_set", "regulatory_timeline", "REGULATORY_TIMELINE"]

CISA_ADVISORIES_URL = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

CACHE_TTL = 6 * 3600        # CISA publica algumas vezes por dia
KEV_TTL = 24 * 3600         # KEV atualiza ~diariamente
STALE_MAX = 7 * 86400       # servir stale por até 7 dias em vez de falhar
HTTP_TIMEOUT = 8.0

# Single-flight: 5 page loads simultâneos não viram 5 fetches upstream.
_fetch_lock = asyncio.Lock()


# ── HTTP ──────────────────────────────────────────────────────────────────────

async def _get(url: str, params: dict | None = None) -> Any:
    import httpx
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
        resp = await client.get(url, params=params, headers={"User-Agent": "PreviSwit-ASPM/1.0"})
        resp.raise_for_status()
        return resp


async def _fetch_cisa() -> list[dict]:
    """Advisories da CISA via Atom/RSS. Usa lxml (já em requirements)."""
    from lxml import etree

    resp = await _get(CISA_ADVISORIES_URL)
    parser = etree.XMLParser(resolve_entities=False, no_network=True, recover=True)
    root = etree.fromstring(resp.content, parser=parser)

    ns = {"a": "http://www.w3.org/2005/Atom"}
    items: list[dict] = []

    # Atom
    for entry in root.findall(".//a:entry", ns)[:25]:
        title = entry.findtext("a:title", default="", namespaces=ns)
        link_el = entry.find("a:link", ns)
        link = link_el.get("href") if link_el is not None else ""
        updated = entry.findtext("a:updated", default="", namespaces=ns)
        summary = entry.findtext("a:summary", default="", namespaces=ns) or ""
        if title:
            items.append({
                "source": "CISA", "source_label": "CISA Advisories",
                "title": title.strip(), "url": link,
                "published_at": updated.strip(),
                "summary": " ".join(summary.split())[:400],
                "kind": "advisory",
            })

    # RSS 2.0 (fallback se o feed mudar de formato)
    if not items:
        for it in root.findall(".//item")[:25]:
            title = it.findtext("title") or ""
            if title:
                items.append({
                    "source": "CISA", "source_label": "CISA Advisories",
                    "title": title.strip(), "url": it.findtext("link") or "",
                    "published_at": it.findtext("pubDate") or "",
                    "summary": " ".join((it.findtext("description") or "").split())[:400],
                    "kind": "advisory",
                })

    return items


async def _fetch_kev() -> dict:
    """Known Exploited Vulnerabilities. Alimenta o exploit_multiplier."""
    resp = await _get(CISA_KEV_URL)
    data = resp.json()
    vulns = data.get("vulnerabilities", []) or []
    return {
        "catalog_version": data.get("catalogVersion"),
        "date_released": data.get("dateReleased"),
        "count": len(vulns),
        "cve_ids": [v.get("cveID") for v in vulns if v.get("cveID")],
        "recent": [
            {
                "cve_id": v.get("cveID"), "vendor": v.get("vendorProject"),
                "product": v.get("product"), "name": v.get("vulnerabilityName"),
                "date_added": v.get("dateAdded"),
                "due_date": v.get("dueDate"),
                "action": v.get("requiredAction"),
            }
            for v in sorted(vulns, key=lambda x: x.get("dateAdded") or "", reverse=True)[:15]
        ],
    }


async def _fetch_nvd() -> list[dict]:
    """CVEs CRITICAL publicadas nos últimos 7 dias."""
    now = datetime.now(timezone.utc)
    params = {
        "cvssV3Severity": "CRITICAL",
        "pubStartDate": (now - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": "20",
    }
    resp = await _get(NVD_CVE_URL, params=params)
    data = resp.json()

    items: list[dict] = []
    for entry in data.get("vulnerabilities", [])[:20]:
        cve = entry.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        descs = cve.get("descriptions", []) or []
        desc = next((d.get("value") for d in descs if d.get("lang") == "en"), "")
        score = None
        for m in (cve.get("metrics", {}) or {}).get("cvssMetricV31", []) or []:
            score = (m.get("cvssData") or {}).get("baseScore")
            if score:
                break
        items.append({
            "source": "NVD", "source_label": "NVD — NIST",
            "title": cve_id, "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "published_at": cve.get("published", ""),
            "summary": " ".join((desc or "").split())[:400],
            "kind": "cve", "cve_id": cve_id, "cvss_score": score,
        })
    return items


# ── Cache + degradação ────────────────────────────────────────────────────────

async def fetch_all(force: bool = False) -> dict:
    """
    Busca todas as fontes com cache e degradação graciosa.

    Fontes são buscadas de forma INDEPENDENTE (`asyncio.gather` com
    `return_exceptions=True`): uma fonte lenta não bloqueia as outras, e uma
    fonte que falha não envenena o resto.
    """
    cache = load_json(FEED_CACHE_FILE, {}) or {}
    now_ts = time.time()
    age = now_ts - float(cache.get("_fetched_at") or 0)

    if cache and age < CACHE_TTL and not force:
        return {**cache, "cache": {"status": "fresh", "age_seconds": int(age)}, "degraded": False}

    async with _fetch_lock:
        # Outra corrotina pode ter preenchido enquanto esperávamos o lock.
        cache = load_json(FEED_CACHE_FILE, {}) or cache
        age = now_ts - float(cache.get("_fetched_at") or 0)
        if cache and age < CACHE_TTL and not force:
            return {**cache, "cache": {"status": "fresh", "age_seconds": int(age)}, "degraded": False}

        kev_age = now_ts - float(cache.get("_kev_fetched_at") or 0)
        need_kev = force or not cache.get("kev") or kev_age > KEV_TTL

        tasks = [_fetch_cisa(), _fetch_nvd()]
        if need_kev:
            tasks.append(_fetch_kev())

        results = await asyncio.gather(*tasks, return_exceptions=True)

        errors: list[str] = []
        cisa = results[0] if not isinstance(results[0], Exception) else None
        nvd = results[1] if not isinstance(results[1], Exception) else None
        kev = results[2] if need_kev and len(results) > 2 and not isinstance(results[2], Exception) else None

        if cisa is None:
            errors.append(f"CISA: {type(results[0]).__name__}")
        if nvd is None:
            errors.append(f"NVD: {type(results[1]).__name__}")
        if need_kev and kev is None and len(results) > 2:
            errors.append(f"KEV: {type(results[2]).__name__}")

        merged = {
            "cisa": cisa if cisa is not None else cache.get("cisa", []),
            "nvd": nvd if nvd is not None else cache.get("nvd", []),
            "kev": kev if kev is not None else cache.get("kev"),
            "_fetched_at": now_ts if (cisa or nvd) else cache.get("_fetched_at", 0),
            "_kev_fetched_at": now_ts if kev else cache.get("_kev_fetched_at", 0),
        }

        if cisa or nvd or kev:
            try:
                save_json(FEED_CACHE_FILE, merged)
            except OSError:
                pass

        has_data = bool(merged["cisa"] or merged["nvd"])
        cache_age = now_ts - float(merged.get("_fetched_at") or 0)

        if not has_data:
            status = "empty"
        elif cisa or nvd:
            status = "fresh"
        elif cache_age < STALE_MAX:
            status = "stale"
        else:
            status = "expired"

        return {
            **merged,
            "cache": {"status": status, "age_seconds": int(cache_age)},
            "degraded": bool(errors),
            "errors": errors,
        }


async def get_kev_set() -> tuple[frozenset[str] | None, dict]:
    """
    Conjunto de CVE IDs do KEV para o `exploit_multiplier`.

    Indisponível -> `(None, meta)`. O scoring então usa `m_exploit = 1.0` e a
    API expõe `kev_available: false`, para o número não mudar em silêncio.
    """
    try:
        data = await fetch_all()
    except Exception as e:
        return None, {"available": False, "reason": type(e).__name__}

    kev = data.get("kev")
    if not kev or not kev.get("cve_ids"):
        return None, {"available": False, "reason": "kev_feed_unavailable"}

    return frozenset(kev["cve_ids"]), {
        "available": True,
        "catalog_version": kev.get("catalog_version"),
        "date_released": kev.get("date_released"),
        "count": kev.get("count"),
    }


# ── Timeline regulatória ──────────────────────────────────────────────────────
#
# Curada, com data e link oficial. `verified_at` existe para tornar VISÍVEL
# qualquer entrada não conferida — o usuário pediu verificável, então a
# estrutura carrega sua própria proveniência.
#
# ATENÇÃO AO IMPLANTAR: conferir cada data e URL contra a fonte oficial antes
# de apresentar a clientes.

_F = "core.posture.taxonomy.Family"

REGULATORY_TIMELINE: list[dict] = [
    {
        "id": "lgpd_vigencia",
        "jurisdiction": "BR",
        "title": "LGPD — Lei nº 13.709/2018 em vigor",
        "authority": "ANPD",
        "effective_date": "2020-09-18",
        "status": "in_force",
        "url": "https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm",
        "frameworks": ["LGPD"],
        "impact": ["SECRETS_MGMT", "CRYPTO_FAILURES", "DATA_PROTECTION", "ACCESS_CONTROL"],
        "summary": (
            "Art. 46 obriga agentes de tratamento a adotar medidas de segurança técnicas e "
            "administrativas aptas a proteger dados pessoais de acessos não autorizados."
        ),
        "verified_at": None,
    },
    {
        "id": "lgpd_sancoes",
        "jurisdiction": "BR",
        "title": "LGPD — sanções administrativas aplicáveis (Art. 52)",
        "authority": "ANPD",
        "effective_date": "2021-08-01",
        "status": "in_force",
        "url": "https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm",
        "frameworks": ["LGPD"],
        "impact": ["DATA_PROTECTION", "SECRETS_MGMT"],
        "summary": (
            "Multa de até 2% do faturamento no Brasil, limitada a R$ 50.000.000 por infração. "
            "Este é o teto ESTATUTÁRIO — um fato legal citável, não uma estimativa de exposição."
        ),
        "statutory_ceiling_brl": 50_000_000,
        "verified_at": None,
    },
    {
        "id": "anpd_res_15_2024",
        "jurisdiction": "BR",
        "title": "Resolução CD/ANPD nº 15/2024 — comunicação de incidente de segurança",
        "authority": "ANPD",
        "effective_date": "2024-04-24",
        "status": "in_force",
        "url": "https://www.gov.br/anpd/pt-br",
        "frameworks": ["LGPD"],
        "impact": ["LOGGING_MONITORING", "DATA_PROTECTION"],
        "summary": (
            "Regulamenta prazo e forma de comunicação de incidente de segurança à ANPD e "
            "aos titulares. Exige capacidade de detecção e registro."
        ),
        "verified_at": None,
    },
    {
        "id": "anpd_res_4_2023",
        "jurisdiction": "BR",
        "title": "Resolução CD/ANPD nº 4/2023 — dosimetria e aplicação de sanções",
        "authority": "ANPD",
        "effective_date": "2023-02-27",
        "status": "in_force",
        "url": "https://www.gov.br/anpd/pt-br",
        "frameworks": ["LGPD"],
        "impact": ["DATA_PROTECTION"],
        "summary": (
            "Define critérios de dosimetria. A adoção comprovada de boas práticas e de "
            "medidas de segurança é atenuante na aplicação de sanções."
        ),
        "verified_at": None,
    },
    {
        "id": "nist_csf_2",
        "jurisdiction": "US",
        "title": "NIST Cybersecurity Framework 2.0 publicado",
        "authority": "NIST",
        "effective_date": "2024-02-26",
        "status": "in_force",
        "url": "https://www.nist.gov/cyberframework",
        "frameworks": ["NIST_CSF_2_0"],
        "impact": ["SEC_MISCONFIG", "VULN_COMPONENTS", "SUPPLY_CHAIN_INTEGRITY"],
        "summary": "Adiciona a função GOVERN (GV) e amplia o escopo para além de infraestrutura crítica.",
        "verified_at": None,
    },
    {
        "id": "iso_27001_transition",
        "jurisdiction": "INT",
        "title": "ISO/IEC 27001 — fim do período de transição 2013 → 2022",
        "authority": "IAF / ISO",
        "effective_date": "2025-10-31",
        "status": "in_force",
        "url": "https://www.iso.org/standard/27001",
        "frameworks": ["ISO_27001_2022"],
        "impact": ["SEC_MISCONFIG", "VULN_COMPONENTS", "SECRETS_MGMT"],
        "summary": (
            "Certificados na versão 2013 deixam de ser válidos. Organizações certificadas "
            "precisam ter migrado para o Anexo A de 2022 (93 controles)."
        ),
        "verified_at": None,
    },
    {
        "id": "pci_dss_4_future_dated",
        "jurisdiction": "INT",
        "title": "PCI DSS v4.0 — requisitos future-dated tornam-se obrigatórios",
        "authority": "PCI SSC",
        "effective_date": "2025-03-31",
        "status": "in_force",
        "url": "https://www.pcisecuritystandards.org/",
        "frameworks": ["PCI_DSS_4_0"],
        "impact": ["VULN_COMPONENTS", "INJECTION", "SEC_MISCONFIG"],
        "summary": (
            "Requisitos antes recomendados passam a ser exigidos, incluindo gestão de "
            "scripts de página de pagamento e varredura automatizada mais frequente."
        ),
        "verified_at": None,
    },
    {
        "id": "eu_nis2",
        "jurisdiction": "EU",
        "title": "NIS2 — prazo de transposição pelos Estados-Membros",
        "authority": "União Europeia",
        "effective_date": "2024-10-17",
        "status": "in_force",
        "url": "https://eur-lex.europa.eu/eli/dir/2022/2555",
        "frameworks": ["ISO_27001_2022", "NIST_CSF_2_0"],
        "impact": ["SUPPLY_CHAIN_INTEGRITY", "VULN_COMPONENTS", "LOGGING_MONITORING"],
        "summary": (
            "Amplia setores cobertos e introduz responsabilização da alta direção. "
            "Relevante para quem tem operação ou clientes na UE."
        ),
        "verified_at": None,
    },
    {
        "id": "eu_cra",
        "jurisdiction": "EU",
        "title": "Cyber Resilience Act — obrigações principais aplicáveis",
        "authority": "União Europeia",
        "effective_date": "2027-12-11",
        "status": "upcoming",
        "url": "https://eur-lex.europa.eu/eli/reg/2024/2847",
        "frameworks": ["ISO_27001_2022"],
        "impact": ["VULN_COMPONENTS", "SUPPLY_CHAIN_INTEGRITY"],
        "summary": (
            "Exige gestão de vulnerabilidades ao longo do ciclo de vida e SBOM para produtos "
            "com elementos digitais comercializados na UE."
        ),
        "verified_at": None,
    },
    {
        "id": "bcb_4893",
        "jurisdiction": "BR",
        "title": "Resolução CMN nº 4.893/2021 — política de segurança cibernética",
        "authority": "Banco Central do Brasil",
        "effective_date": "2021-07-01",
        "status": "in_force",
        "url": "https://www.bcb.gov.br/",
        "frameworks": ["ISO_27001_2022", "PCI_DSS_4_0"],
        "impact": ["SEC_MISCONFIG", "CRYPTO_FAILURES", "LOGGING_MONITORING"],
        "summary": (
            "Obriga instituições financeiras a manter política de segurança cibernética e "
            "requisitos para contratação de serviços de processamento em nuvem."
        ),
        "verified_at": None,
    },
]


def regulatory_timeline(family_damage: dict[str, float], now: datetime | None = None) -> list[dict]:
    """
    Enriquece a timeline com relevância computada.

    `applies_to_you` é verdadeiro quando alguma família impactada pela norma
    tem dano aberto — é isso que impede a timeline de ser mera decoração.
    """
    now = now or datetime.now(timezone.utc)
    out: list[dict] = []

    for item in REGULATORY_TIMELINE:
        try:
            eff = datetime.fromisoformat(item["effective_date"]).replace(tzinfo=timezone.utc)
            days = (eff - now).days
        except (ValueError, KeyError):
            days = None

        impacted = [fam for fam in item.get("impact", []) if family_damage.get(fam, 0) > 0]

        out.append({
            **item,
            "days_until_effective": days,
            "applies_to_you": bool(impacted),
            "impacted_families_with_findings": impacted,
            "related_damage": round(sum(family_damage.get(f, 0.0) for f in impacted), 2),
        })

    # Aplicáveis primeiro, depois por data mais recente.
    out.sort(key=lambda x: (not x["applies_to_you"], x.get("effective_date") or ""), reverse=False)
    return out
