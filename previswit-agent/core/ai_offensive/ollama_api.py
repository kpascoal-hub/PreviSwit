"""
core/ai_offensive/ollama_api.py
Integration with Ollama local LLM (whiterabbitneo model).
Falls back to a mock AI response if Ollama is not running.
"""

import json
import logging
import os

import requests
from dotenv import load_dotenv

load_dotenv()  # loads variables from .env into os.environ

logger = logging.getLogger(__name__)

OLLAMA_URL: str = os.getenv("OLLAMA_API_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "whiterabbitneo")
OLLAMA_TIMEOUT: int = int(os.getenv("OLLAMA_TIMEOUT", "120"))  # seconds

_MOCK_AI_RESPONSE: dict = {
    "source": "ollama",
    "model": OLLAMA_MODEL,
    "mock": True,
    "validated": True,
    "risk_confirmed": True,
    "suggested_patch": (
        "1. Update the affected package to the latest patched version.\n"
        "2. Apply vendor-recommended mitigations (WAF rules, network segmentation).\n"
        "3. Audit all code paths that invoke the vulnerable component.\n"
        "4. Re-scan after remediation to confirm the finding is resolved."
    ),
    "message": "Ollama not reachable — returning default mock patch guidance.",
}


def _build_prompt(vuln_data: dict) -> str:
    """Build a structured prompt from vulnerability data."""
    vuln_id = vuln_data.get("vulnerability_id") or vuln_data.get("template_id", "UNKNOWN")
    name = vuln_data.get("name") or vuln_data.get("title", "Unknown Vulnerability")
    severity = vuln_data.get("severity", "unknown").upper()
    description = vuln_data.get("description", "No description provided.")

    return (
        f"You are an offensive security expert and patch advisor.\n"
        f"Analyze the following vulnerability and respond with:\n"
        f"1. Whether the risk is confirmed (yes/no)\n"
        f"2. A concise remediation patch or mitigation steps\n\n"
        f"Vulnerability ID : {vuln_id}\n"
        f"Name             : {name}\n"
        f"Severity         : {severity}\n"
        f"Description      : {description}\n"
    )


def validate_vuln(vuln_data: dict) -> dict:
    """
    Send a vulnerability to the local Ollama LLM for validation and patch advice.

    Args:
        vuln_data: A finding dict from any scanner runner (nmap, nuclei, trivy).

    Returns:
        dict with keys:
            - source          (str)  : "ollama"
            - model           (str)  : model name used
            - mock            (bool) : True when falling back to mock
            - validated       (bool) : whether the AI confirmed the risk
            - risk_confirmed  (bool) : alias for validated
            - suggested_patch (str)  : AI-generated remediation guidance
            - message         (str)  : optional informational message
    """
    if not isinstance(vuln_data, dict):
        raise TypeError(f"vuln_data must be a dict, got {type(vuln_data).__name__}")

    prompt = _build_prompt(vuln_data)
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
    }

    logger.info("Sending vuln '%s' to Ollama for validation.", vuln_data.get("vulnerability_id") or vuln_data.get("template_id", "?"))

    try:
        response = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=OLLAMA_TIMEOUT,
        )
        response.raise_for_status()

        data = response.json()
        ai_text: str = data.get("response", "").strip()

        risk_confirmed = "yes" in ai_text[:200].lower()

        return {
            "source": "ollama",
            "model": OLLAMA_MODEL,
            "mock": False,
            "validated": True,
            "risk_confirmed": risk_confirmed,
            "suggested_patch": ai_text,
            "message": "",
        }

    except requests.exceptions.ConnectionError:
        logger.warning("Cannot connect to Ollama at %s. Returning mock response.", OLLAMA_URL)
        return _MOCK_AI_RESPONSE

    except requests.exceptions.Timeout:
        logger.error("Ollama request timed out after %ds.", OLLAMA_TIMEOUT)
        return {
            "source": "ollama",
            "model": OLLAMA_MODEL,
            "mock": False,
            "validated": False,
            "risk_confirmed": False,
            "suggested_patch": "",
            "message": f"Request to Ollama timed out after {OLLAMA_TIMEOUT}s.",
        }

    except requests.exceptions.HTTPError as exc:
        logger.error("Ollama HTTP error: %s", exc)
        return {
            "source": "ollama",
            "model": OLLAMA_MODEL,
            "mock": False,
            "validated": False,
            "risk_confirmed": False,
            "suggested_patch": "",
            "message": f"HTTP error: {exc}",
        }

    except (json.JSONDecodeError, KeyError) as exc:
        logger.error("Failed to parse Ollama response: %s", exc)
        return {
            "source": "ollama",
            "model": OLLAMA_MODEL,
            "mock": False,
            "validated": False,
            "risk_confirmed": False,
            "suggested_patch": "",
            "message": f"Parse error: {exc}",
        }
