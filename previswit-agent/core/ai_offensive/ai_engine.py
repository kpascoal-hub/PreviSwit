"""
core/ai_offensive/ai_engine.py

Cliente resiliente para a API do OpenRouter (meta-llama/llama-3.3-70b-instruct:free).

Armaduras implementadas:
    1. Timeout     — 120 s por requisição para aguentar a lentidão da API gratuita.
    2. Retries     — até 3 tentativas com 5 s de espera entre elas.
    3. JSON Guard  — o prompt força JSON puro; json.loads valida a resposta;
                     JSON inválido dispara retry automático.
"""

import json
import logging
import os
import time

import requests
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------

load_dotenv()

logger = logging.getLogger(__name__)

_OPENROUTER_URL: str = "https://openrouter.ai/api/v1/chat/completions"
_MODEL: str = "meta-llama/llama-3.3-70b-instruct:free"
_MAX_RETRIES: int = 3
_RETRY_DELAY: float = 5.0   # segundos entre tentativas
_TIMEOUT: int = 120          # Armadura 1 — aguenta até 120 s de resposta

# Resposta de fallback segura retornada quando todas as 3 tentativas falham.
_FALLBACK_RESPONSE: dict = {
    "source": "openrouter",
    "model": _MODEL,
    "mock": True,
    "validated": False,
    "risk_confirmed": False,
    "payload_teste": "",
    "codigo_correcao": (
        "1. Atualize o pacote afetado para a versão mais recente com patch.\n"
        "2. Aplique mitigações recomendadas pelo fornecedor (regras WAF, segmentação de rede).\n"
        "3. Audite todos os caminhos de código que invocam o componente vulnerável.\n"
        "4. Refaça o scan após a remediação para confirmar que o achado foi resolvido."
    ),
    "message": "OpenRouter não retornou um JSON válido após 3 tentativas — resposta de fallback segura.",
}


# ---------------------------------------------------------------------------
# Funções internas
# ---------------------------------------------------------------------------

def _get_api_key() -> str:
    """Lê a OPENROUTER_API_KEY do .env / ambiente e valida presença."""
    key = os.getenv("OPENROUTER_API_KEY", "").strip()
    if not key:
        raise EnvironmentError(
            "OPENROUTER_API_KEY não encontrada. "
            "Adicione-a ao arquivo .env antes de usar o ai_engine."
        )
    return key


def _build_prompt(vuln_data: dict) -> str:
    """
    Monta o prompt com contexto da vulnerabilidade.

    O encerramento obrigatório instrui a IA a devolver **apenas** JSON puro,
    sem blocos markdown nem texto explicativo — Armadura 3.
    """
    vuln_id = vuln_data.get("vulnerability_id") or vuln_data.get("template_id", "UNKNOWN")
    name = vuln_data.get("name") or vuln_data.get("title", "Unknown Vulnerability")
    severity = vuln_data.get("severity", "unknown").upper()
    description = vuln_data.get("description", "No description provided.")

    # Armadura 3 — encerramento exato exigido pelo requisito
    json_instruction = (
        'Responda APENAS com um JSON válido no formato: '
        '{"payload_teste": "", "codigo_correcao": ""}. '
        'Sem formatação markdown, sem explicações extras.'
    )

    return (
        f"Você é um especialista em segurança ofensiva e consultor de patches.\n"
        f"Analise a vulnerabilidade abaixo e preencha os campos do JSON:\n"
        f"  • payload_teste   : um payload de prova-de-conceito para explorar a falha (string).\n"
        f"  • codigo_correcao : passos de remediação ou patch de código (string).\n\n"
        f"Vulnerability ID : {vuln_id}\n"
        f"Name             : {name}\n"
        f"Severity         : {severity}\n"
        f"Description      : {description}\n\n"
        f"{json_instruction}"
    )


def _post_to_openrouter(prompt: str, api_key: str) -> requests.Response:
    """
    Executa o POST para a API do OpenRouter com timeout e headers obrigatórios.

    Raises:
        requests.exceptions.Timeout: se a resposta demorar mais de _TIMEOUT s.
        requests.exceptions.RequestException: para qualquer outro erro de rede.
    """
    headers = {
        "Authorization": f"Bearer {api_key}",
        "HTTP-Referer": "http://localhost:8000",
        "Content-Type": "application/json",
    }
    body = {
        "model": _MODEL,
        "messages": [
            {"role": "user", "content": prompt},
        ],
    }

    return requests.post(
        _OPENROUTER_URL,
        headers=headers,
        json=body,
        timeout=_TIMEOUT,   # Armadura 1
    )


def _extract_json(response: requests.Response) -> dict:
    """
    Extrai e valida o JSON da resposta da API.

    A IA às vezes envolve a resposta em ```json ... ``` mesmo com instrução
    contrária. Esta função limpa esse artefato antes de parsear.

    Raises:
        ValueError: se o conteúdo não puder ser parseado como JSON válido.
    """
    api_json = response.json()
    ai_text: str = (
        api_json["choices"][0]["message"]["content"].strip()
    )

    # Remove blocos markdown residuais (```json ... ``` ou ``` ... ```)
    if ai_text.startswith("```"):
        lines = ai_text.splitlines()
        # Remove primeira linha (```json ou ```) e última (```)
        ai_text = "\n".join(lines[1:-1]).strip()

    # Armadura 3 — json.loads valida o JSON; levanta ValueError se inválido
    parsed: dict = json.loads(ai_text)

    # Garante que as chaves esperadas existem
    if "payload_teste" not in parsed or "codigo_correcao" not in parsed:
        raise ValueError(
            f"JSON parseado não contém as chaves esperadas: {list(parsed.keys())}"
        )

    return parsed


# ---------------------------------------------------------------------------
# API pública
# ---------------------------------------------------------------------------

def validate_vuln(vuln_data: dict) -> dict:
    """
    Envia uma vulnerabilidade ao OpenRouter para análise ofensiva.

    Implementa 3 armaduras de resiliência:
        1. Timeout de 120 s por requisição.
        2. Até 3 tentativas com 5 s de espera entre elas.
        3. Prompt que força JSON puro + validação por json.loads.

    Args:
        vuln_data: Dicionário de achado de qualquer runner de scanner
                   (nmap, nuclei, trivy).

    Returns:
        dict com as chaves:
            source          (str)  : "openrouter"
            model           (str)  : modelo utilizado
            mock            (bool) : True quando retornando fallback
            validated       (bool) : True se a IA respondeu com sucesso
            risk_confirmed  (bool) : sempre True quando validated=True
            payload_teste   (str)  : payload PoC gerado pela IA
            codigo_correcao (str)  : passos de remediação gerados pela IA
            message         (str)  : mensagem informativa (vazia em sucesso)
    """
    if not isinstance(vuln_data, dict):
        raise TypeError(f"vuln_data deve ser dict, recebido: {type(vuln_data).__name__}")

    api_key = _get_api_key()
    prompt = _build_prompt(vuln_data)
    vuln_id = vuln_data.get("vulnerability_id") or vuln_data.get("template_id", "?")

    last_error: str = ""

    # Armadura 2 — loop de retries
    for attempt in range(1, _MAX_RETRIES + 1):
        logger.info(
            "[OpenRouter] Tentativa %d/%d para vuln '%s'.",
            attempt, _MAX_RETRIES, vuln_id,
        )

        try:
            response = _post_to_openrouter(prompt, api_key)

            # Verifica status HTTP — 200 é o único aceitável
            if response.status_code != 200:
                last_error = (
                    f"Status HTTP inesperado: {response.status_code} — {response.text[:200]}"
                )
                logger.warning("[OpenRouter] %s. Aguardando %gs...", last_error, _RETRY_DELAY)
                time.sleep(_RETRY_DELAY)
                continue

            # Armadura 3 — extrai e valida o JSON
            parsed = _extract_json(response)

            logger.info(
                "[OpenRouter] ✅ Resposta válida recebida na tentativa %d para '%s'.",
                attempt, vuln_id,
            )

            return {
                "source": "openrouter",
                "model": _MODEL,
                "mock": False,
                "validated": True,
                "risk_confirmed": True,
                "payload_teste": parsed.get("payload_teste", ""),
                "codigo_correcao": parsed.get("codigo_correcao", ""),
                "message": "",
            }

        except requests.exceptions.Timeout:
            last_error = f"Timeout após {_TIMEOUT}s na tentativa {attempt}."
            logger.warning("[OpenRouter] ⏱ %s. Aguardando %gs...", last_error, _RETRY_DELAY)

        except requests.exceptions.RequestException as exc:
            last_error = f"Erro de rede na tentativa {attempt}: {exc}"
            logger.warning("[OpenRouter] 🌐 %s. Aguardando %gs...", last_error, _RETRY_DELAY)

        except (json.JSONDecodeError, ValueError, KeyError) as exc:
            last_error = f"JSON inválido na tentativa {attempt}: {exc}"
            logger.warning("[OpenRouter] ⚠ %s. Aguardando %gs...", last_error, _RETRY_DELAY)

        # Só dorme entre tentativas, não após a última
        if attempt < _MAX_RETRIES:
            time.sleep(_RETRY_DELAY)

    # Todas as tentativas esgotadas — retorna fallback seguro
    logger.error(
        "[OpenRouter] ❌ Todas as %d tentativas falharam para '%s'. Último erro: %s",
        _MAX_RETRIES, vuln_id, last_error,
    )

    fallback = dict(_FALLBACK_RESPONSE)
    fallback["message"] = f"Falhou após {_MAX_RETRIES} tentativas. Último erro: {last_error}"
    return fallback
