"""
core/scanners/trivy_runner.py
Wrapper for the Trivy filesystem vulnerability scanner.
Executes `trivy fs <target_dir> --format json` via subprocess, parses
the JSON output, and flattens the nested Results into a flat findings list.
Falls back to mock data when the trivy binary is unavailable.
"""

import json
import subprocess
import logging

logger = logging.getLogger(__name__)

_MOCK_RESULT: dict = {
    "source": "trivy",
    "mock": True,
    "status": "success",
    "findings": [
        {
            "vulnerability_id": "CVE-2023-0464",
            "pkg_name": "openssl",
            "installed_version": "3.0.2",
            "fixed_version": "3.0.9",
            "severity": "high",
            "title": "OpenSSL: Denial of service via excessive certificate chain depth",
            "description": "Excessive resource usage verifying X.509 policy constraints.",
        },
        {
            "vulnerability_id": "CVE-2022-4450",
            "pkg_name": "openssl",
            "installed_version": "3.0.2",
            "fixed_version": "3.0.8",
            "severity": "medium",
            "title": "OpenSSL: Double free after calling PEM_read_bio_ex",
            "description": "Double free can be triggered attacker can supply a malicious PEM file.",
        },
    ],
    "message": "trivy not found or integration pending — returning mock data.",
}


def _flatten_results(raw: dict) -> list[dict]:
    """
    Flatten Trivy's nested Results structure into a plain list of findings.

    Trivy JSON schema (fs mode):
      {
        "Results": [
          {
            "Target": "...",
            "Type": "...",
            "Vulnerabilities": [ { "VulnerabilityID": ..., ... }, ... ]
          },
          ...
        ]
      }
    """
    findings: list[dict] = []
    for result_block in raw.get("Results") or []:
        target = result_block.get("Target", "")
        vuln_type = result_block.get("Type", "")
        for vuln in result_block.get("Vulnerabilities") or []:
            findings.append(
                {
                    "vulnerability_id": vuln.get("VulnerabilityID", ""),
                    "pkg_name": vuln.get("PkgName", ""),
                    "installed_version": vuln.get("InstalledVersion", ""),
                    "fixed_version": vuln.get("FixedVersion", ""),
                    "severity": vuln.get("Severity", "").lower(),
                    "title": vuln.get("Title", ""),
                    "description": vuln.get("Description", ""),
                    "target": target,
                    "type": vuln_type,
                }
            )
    return findings


def run_trivy(target_dir: str = ".") -> dict:
    """
    Execute `trivy fs <target_dir> --format json` and return parsed findings.

    Args:
        target_dir: Filesystem path to scan (defaults to current directory).

    Returns:
        dict with keys:
            - source   (str)       : "trivy"
            - mock     (bool)      : True when falling back to mock data
            - status   (str)       : "success" | "error"
            - findings (list[dict]): Flattened vulnerability findings
            - message  (str)       : optional informational message
    """
    if not target_dir or not isinstance(target_dir, str):
        raise ValueError("target_dir must be a non-empty string.")

    cmd = ["trivy", "fs", target_dir, "--format", "json"]
    logger.info("Running trivy: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,
        )

        if result.returncode != 0:
            logger.warning(
                "trivy exited with code %d: %s", result.returncode, result.stderr
            )
            return {
                "source": "trivy",
                "mock": False,
                "status": "error",
                "findings": [],
                "message": result.stderr.strip(),
            }

        raw: dict = json.loads(result.stdout) if result.stdout.strip() else {}
        findings = _flatten_results(raw)
        logger.info("trivy found %d finding(s) in %s", len(findings), target_dir)
        return {
            "source": "trivy",
            "mock": False,
            "status": "success",
            "findings": findings,
            "message": "",
        }

    except FileNotFoundError:
        logger.warning("trivy binary not found. Returning mock data.")
        return _MOCK_RESULT

    except subprocess.TimeoutExpired:
        logger.error("trivy timed out scanning %s", target_dir)
        return {
            "source": "trivy",
            "mock": False,
            "status": "error",
            "findings": [],
            "message": f"Scan timed out for target: {target_dir}",
        }

    except json.JSONDecodeError as exc:
        logger.error("Failed to parse trivy JSON output: %s", exc)
        return {
            "source": "trivy",
            "mock": False,
            "status": "error",
            "findings": [],
            "message": f"JSON parse error: {exc}",
        }

    except Exception as exc:  # pragma: no cover
        logger.error("Unexpected error running trivy: %s", exc)
        return {
            "source": "trivy",
            "mock": True,
            "status": "error",
            "findings": [],
            "message": f"Unexpected error: {exc}",
        }
