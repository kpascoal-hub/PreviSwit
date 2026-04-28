"""
core/scanners/nuclei_runner.py
Wrapper for the Nuclei vulnerability scanner.
Executes `nuclei -u <target_url> -json` via subprocess and parses
its JSONL output (one JSON object per finding per line).
Falls back to mock data when the nuclei binary is unavailable.
"""

import json
import subprocess
import logging

logger = logging.getLogger(__name__)

_MOCK_RESULT: dict = {
    "source": "nuclei",
    "mock": True,
    "status": "success",
    "findings": [
        {
            "template_id": "CVE-2021-44228",
            "name": "Log4Shell Remote Code Execution",
            "severity": "critical",
            "host": "http://192.168.1.1",
            "matched_at": "http://192.168.1.1/app",
            "description": "Apache Log4j2 <=2.14.1 JNDI features RCE vulnerability.",
        },
        {
            "template_id": "CVE-2022-22965",
            "name": "Spring4Shell RCE",
            "severity": "high",
            "host": "http://192.168.1.1",
            "matched_at": "http://192.168.1.1/spring",
            "description": "Spring Framework RCE via DataBinder.",
        },
    ],
    "message": "nuclei not found or integration pending — returning mock data.",
}


def run_nuclei(target_url: str) -> dict:
    """
    Execute `nuclei -u <target_url> -json` and return parsed findings.

    Args:
        target_url: The URL to scan with Nuclei.

    Returns:
        dict with keys:
            - source   (str)       : "nuclei"
            - mock     (bool)      : True when falling back to mock data
            - status   (str)       : "success" | "error"
            - findings (list[dict]): Parsed vulnerability findings
            - message  (str)       : optional informational message
    """
    if not target_url or not isinstance(target_url, str):
        raise ValueError("target_url must be a non-empty string.")

    cmd = ["nuclei", "-u", target_url, "-json"]
    logger.info("Running nuclei: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )

        if result.returncode != 0:
            logger.warning("nuclei exited with code %d: %s", result.returncode, result.stderr)
            return {
                "source": "nuclei",
                "mock": False,
                "status": "error",
                "findings": [],
                "message": result.stderr.strip(),
            }

        # Parse JSONL output: nuclei emits one JSON object per line
        findings: list[dict] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError as parse_err:
                logger.debug("Skipping non-JSON nuclei line: %s | error: %s", line, parse_err)

        logger.info("nuclei found %d finding(s) for %s", len(findings), target_url)
        return {
            "source": "nuclei",
            "mock": False,
            "status": "success",
            "findings": findings,
            "message": "",
        }

    except FileNotFoundError:
        logger.warning("nuclei binary not found. Returning mock data.")
        return _MOCK_RESULT

    except subprocess.TimeoutExpired:
        logger.error("nuclei timed out scanning %s", target_url)
        return {
            "source": "nuclei",
            "mock": False,
            "status": "error",
            "findings": [],
            "message": f"Scan timed out for target: {target_url}",
        }

    except Exception as exc:  # pragma: no cover
        logger.error("Unexpected error running nuclei: %s", exc)
        return {
            "source": "nuclei",
            "mock": True,
            "status": "error",
            "findings": [],
            "message": f"Unexpected error: {exc}",
        }
