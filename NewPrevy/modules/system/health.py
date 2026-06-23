"""
PreviSwit — Agent Health & Capabilities Module
===============================================
Verifica fisicamente as ferramentas de pentest instaladas no container
e as chaves de API/integrações configuradas via variáveis de ambiente.

Uso:
    from modules.system.health import get_agent_capabilities
    caps = get_agent_capabilities()
"""

import os
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Optional

# ─── Catálogo de ferramentas de pentest ──────────────────────────────────────
# Cada entrada define o binário a verificar e metadados para o frontend.
PENTEST_TOOLS_CATALOG = [
    {
        "id":     "nmap",
        "name":   "Nmap",
        "desc":   "Scanner de Rede e Portas",
        "icon":   "🗺️",
        "color":  "green",
        "binary": "nmap",
    },
    {
        "id":     "nuclei",
        "name":   "Nuclei",
        "desc":   "Scanner de Vulnerabilidades (Templates)",
        "icon":   "🔍",
        "color":  "orange",
        "binary": "nuclei",
    },
    {
        "id":     "trivy",
        "name":   "Trivy",
        "desc":   "Scanner de Containers e SCA",
        "icon":   "🛡️",
        "color":  "red",
        "binary": "trivy",
    },
    {
        "id":     "gobuster",
        "name":   "Gobuster",
        "desc":   "Enumeração de Diretórios e Subdomínios",
        "icon":   "📂",
        "color":  "yellow",
        "binary": "gobuster",
    },
]

# ─── Catálogo de integrações de API ─────────────────────────────────────────
# Verifica se a chave de ambiente está presente e não-vazia.
API_INTEGRATIONS_CATALOG = [
    {
        "id":      "gemini",
        "name":    "Google Gemini",
        "desc":    "Motor de IA Generativa",
        "icon":    "🤖",
        "color":   "blue",
        "env_key": "GEMINI_API_KEY",
    },
    {
        "id":      "jira",
        "name":    "Jira",
        "desc":    "Gestão de Issues e Ticketing",
        "icon":    "🎫",
        "color":   "indigo",
        "env_key": "JIRA_API_TOKEN",
    },
    {
        "id":      "slack",
        "name":    "Slack",
        "desc":    "Alertas e Notificações em Tempo Real",
        "icon":    "💬",
        "color":   "purple",
        "env_key": "SLACK_BOT_TOKEN",
    },
    {
        "id":      "virustotal",
        "name":    "VirusTotal",
        "desc":    "Threat Intelligence e IOCs",
        "icon":    "🦠",
        "color":   "red",
        "env_key": "VIRUSTOTAL_API_KEY",
    },
    {
        "id":      "shodan",
        "name":    "Shodan",
        "desc":    "OSINT / Discovery de Ativos Expostos",
        "icon":    "🌐",
        "color":   "teal",
        "env_key": "SHODAN_API_KEY",
    },
]


def _get_binary_version(binary: str, path: str) -> Optional[str]:
    """
    Tenta obter a versão do binário de forma não-bloqueante.
    Retorna uma string curta (ex: '7.95') ou None em caso de erro.
    """
    version_flags = {
        "nmap":     ["--version"],
        "nuclei":   ["-version"],
        "trivy":    ["--version"],
        "gobuster": ["version"],
    }
    flags = version_flags.get(binary, ["--version"])
    try:
        result = subprocess.run(
            [path] + flags,
            capture_output=True,
            text=True,
            timeout=5,
        )
        # Pega a primeira linha não-vazia da saída
        output = (result.stdout or result.stderr or "").strip()
        first_line = next((l.strip() for l in output.splitlines() if l.strip()), "")
        # Trunca para evitar payloads enormes
        return first_line[:80] if first_line else None
    except Exception:
        return None


def _check_pentest_tool(tool: dict) -> dict:
    """Verifica se um binário de pentest está disponível no PATH."""
    binary = tool["binary"]
    path = shutil.which(binary)
    active = path is not None

    entry = {
        "id":     tool["id"],
        "name":   tool["name"],
        "desc":   tool["desc"],
        "icon":   tool["icon"],
        "color":  tool["color"],
        "active": active,
        "path":   path,
        "version": None,
    }

    if active:
        entry["version"] = _get_binary_version(binary, path)

    return entry


def _check_api_integration(integration: dict) -> dict:
    """Verifica se a chave de API está configurada via variável de ambiente."""
    env_val = os.getenv(integration["env_key"], "").strip()
    active = bool(env_val)

    return {
        "id":     integration["id"],
        "name":   integration["name"],
        "desc":   integration["desc"],
        "icon":   integration["icon"],
        "color":  integration["color"],
        "active": active,
        # Nunca expõe o valor real da chave — apenas confirma presença
        "configured_key": integration["env_key"],
    }


def get_agent_capabilities() -> dict:
    """
    Coleta e retorna as capacidades reais do agente:
      - Ferramentas de pentest instaladas (via shutil.which)
      - Integrações de API configuradas (via variáveis de ambiente)

    Returns:
        dict com as chaves:
          - pentest_tools: list[dict]
          - api_integrations: list[dict]
          - reported_at: str (ISO 8601 UTC)
          - agent_id: str
    """
    pentest_tools = [_check_pentest_tool(t) for t in PENTEST_TOOLS_CATALOG]
    api_integrations = [_check_api_integration(a) for a in API_INTEGRATIONS_CATALOG]

    active_tools = sum(1 for t in pentest_tools if t["active"])
    active_apis  = sum(1 for a in api_integrations if a["active"])

    return {
        "agent_id":         os.getenv("PREVISWIT_AGENT_ID", "agent_01"),
        "reported_at":      datetime.now(timezone.utc).isoformat(),
        "pentest_tools":    pentest_tools,
        "api_integrations": api_integrations,
        "summary": {
            "total_tools":   len(pentest_tools),
            "active_tools":  active_tools,
            "total_apis":    len(api_integrations),
            "active_apis":   active_apis,
        },
    }
