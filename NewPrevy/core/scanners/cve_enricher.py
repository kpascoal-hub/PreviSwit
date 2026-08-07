"""
PreviSwit AI-ASPM — core/scanners/cve_enricher.py
Extrai CVE IDs dos resultados Trivy/Semgrep e enriquece via OSV.dev.

Fluxo:
  1. extract_cves_from_trivy()  — CVE IDs já identificados pelo Trivy
  2. extract_cves_from_semgrep() — refs de CVE/CWE nos metadados das regras
  3. enrich_with_osv()          — detalha cada CVE via GET api.osv.dev/v1/vulns/{id}
  4. build_cve_report()         — ponto de entrada: junta tudo num relatório estruturado

OSV.dev: API pública do Google, sem autenticação, cobre NVD/CVE + GitHub Advisory.
"""

import logging
from typing import Optional

import requests

log = logging.getLogger("previswit.cve_enricher")

_OSV_BASE = "https://api.osv.dev/v1"
_TIMEOUT  = 8  # segundos por request


# ── Extração ──────────────────────────────────────────────────────────────────

def extract_cves_from_trivy(trivy_data: dict) -> list[dict]:
    """
    Percorre o JSON do Trivy e extrai cada CVE com severidade e versão afetada.
    O Trivy já bate contra a NVD — só precisamos colher o que ele retornou.
    """
    cves = []
    for result in trivy_data.get("Results", []):
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []):
            cve_id = vuln.get("VulnerabilityID", "")
            if not cve_id.startswith("CVE-"):
                continue
            cves.append({
                "id":                cve_id,
                "package":           vuln.get("PkgName", ""),
                "installed_version": vuln.get("InstalledVersion", ""),
                "fixed_version":     vuln.get("FixedVersion", ""),
                "severity":          vuln.get("Severity", "UNKNOWN"),
                "cvss_score":        _extract_cvss(vuln),
                "title":             vuln.get("Title", ""),
                "target_file":       target,
                "source":            "trivy",
            })
    return cves


def extract_cves_from_semgrep(semgrep_data: dict) -> list[dict]:
    """
    Lê os metadados de cada regra Semgrep e extrai referências a CVE.
    Nem todas as regras têm CVE — é oportunístico.
    """
    refs = []
    for finding in semgrep_data.get("results", []):
        meta    = finding.get("extra", {}).get("metadata", {})
        cve_raw = meta.get("cve", [])
        if isinstance(cve_raw, str):
            cve_raw = [cve_raw]

        for cve_id in cve_raw:
            if not cve_id.startswith("CVE-"):
                continue
            refs.append({
                "id":       cve_id,
                "rule":     finding.get("check_id", ""),
                "file":     finding.get("path", ""),
                "line":     finding.get("start", {}).get("line"),
                "severity": finding.get("extra", {}).get("severity", "UNKNOWN"),
                "message":  finding.get("extra", {}).get("message", ""),
                "source":   "semgrep",
            })
    return refs


# ── Enriquecimento OSV.dev ────────────────────────────────────────────────────

def enrich_with_osv(cve_ids: list[str]) -> dict[str, dict]:
    """
    Para cada CVE ID único, chama GET /v1/vulns/{id} no OSV.dev.
    Falhas individuais são logadas e ignoradas — não interrompem o scan.
    Retorna { "CVE-XXXX-YYYY": { summary, details, published, severity, references } }.
    """
    enriched: dict[str, dict] = {}
    for cve_id in set(cve_ids):
        try:
            r = requests.get(f"{_OSV_BASE}/vulns/{cve_id}", timeout=_TIMEOUT)
            if r.status_code == 200:
                data = r.json()
                enriched[cve_id] = {
                    "summary":    data.get("summary", ""),
                    "details":    (data.get("details") or "")[:600],
                    "published":  data.get("published", ""),
                    "modified":   data.get("modified", ""),
                    "severity":   _osv_severity(data),
                    "references": [ref.get("url") for ref in data.get("references", [])[:3]],
                }
            else:
                log.debug("OSV.dev: %s não encontrado (HTTP %d)", cve_id, r.status_code)
        except Exception as exc:
            log.warning("OSV.dev: falha ao enriquecer %s — %s", cve_id, exc)
    return enriched


# ── Relatório consolidado ─────────────────────────────────────────────────────

def build_cve_report(trivy_data: dict, semgrep_data: dict) -> dict:
    """
    Ponto de entrada principal.
    Extrai CVEs de Trivy + Semgrep, enriquece via OSV.dev e retorna relatório.

    Args:
        trivy_data:   JSON completo retornado pelo Trivy (pode ser {})
        semgrep_data: JSON completo retornado pelo Semgrep (pode ser {})

    Returns:
        {
          "total":              int,
          "unique_cve_ids":     list[str],
          "trivy_findings":     list[dict],   # com campos OSV mesclados
          "semgrep_findings":   list[dict],   # com campos OSV mesclados
          "osv_enriched_count": int,
        }
    """
    trivy_cves   = extract_cves_from_trivy(trivy_data)
    semgrep_cves = extract_cves_from_semgrep(semgrep_data)

    all_ids = list({c["id"] for c in trivy_cves + semgrep_cves})
    osv     = enrich_with_osv(all_ids) if all_ids else {}

    def _merge(cve: dict) -> dict:
        return {**cve, **osv.get(cve["id"], {})}

    return {
        "total":              len(trivy_cves) + len(semgrep_cves),
        "unique_cve_ids":     all_ids,
        "trivy_findings":     [_merge(c) for c in trivy_cves],
        "semgrep_findings":   [_merge(c) for c in semgrep_cves],
        "osv_enriched_count": len(osv),
    }


# ── Helpers internos ──────────────────────────────────────────────────────────

def _extract_cvss(vuln: dict) -> Optional[float]:
    """Extrai o CVSS score mais alto disponível num objeto de vulnerabilidade Trivy."""
    for key in ("V3Score", "V2Score"):
        val = vuln.get(key)
        if isinstance(val, (int, float)):
            return float(val)

    cvss_map = vuln.get("CVSS", {})
    if isinstance(cvss_map, dict):
        scores = []
        for provider in cvss_map.values():
            if isinstance(provider, dict):
                for score_key in ("V3Score", "V2Score"):
                    s = provider.get(score_key)
                    if s is not None:
                        scores.append(float(s))
        if scores:
            return max(scores)
    return None


def _osv_severity(data: dict) -> str:
    """Mapeia CVSS score do OSV para label de severidade."""
    for sev in data.get("severity", []):
        if sev.get("type") in ("CVSS_V3", "CVSS_V4"):
            try:
                score = float(sev.get("score", 0))
            except (TypeError, ValueError):
                continue
            if score >= 9.0:
                return "CRITICAL"
            if score >= 7.0:
                return "HIGH"
            if score >= 4.0:
                return "MEDIUM"
            return "LOW"
    return "UNKNOWN"
