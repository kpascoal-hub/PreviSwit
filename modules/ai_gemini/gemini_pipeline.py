"""
PreviSwit — Pipeline 6: Gemini Active Attacker
===============================================

Módulo ofensivo que utiliza a API do Google Gemini para gerar e testar
payloads direcionados com base nos dados de reconhecimento e scanners.

A IA recebe os dados do scan e retorna ataques estruturados que este
módulo executa ativamente no alvo para validação imediata.
"""

import os
import json
import logging
import requests
import urllib3

from google import genai
from google.genai import types

from core.utils import print_status

# Desativa avisos de InsecureRequestWarning para certificados auto-assinados
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("gemini_attacker")

# ─── Constantes ──────────────────────────────────────────────────────────────

MODEL_NAME = "gemini-2.5-flash"

SYSTEM_PROMPT = """\
Você é um **Offensive Security Payload Generator** especialista em Web Application Security.
Você receberá dados brutos de reconhecimento e escaneamento do PreviSwit (endpoints, parâmetros, headers, portas).
Sua função é gerar payloads ofensivos direcionados para testar vulnerabilidades reais no alvo.

Retorne EXCLUSIVAMENTE um JSON com uma lista de ataques a serem testados.
Siga rigorosamente este schema:

```json
{
  "targeted_attacks": [
    {
      "url": "<endpoint alvo completo>",
      "method": "GET|POST|PUT|DELETE",
      "headers": {"Content-Type": "application/json"},
      "data": "<payload ofensivo, ex: ' OR 1=1 --> ou json>",
      "is_json": true,
      "vulnerability_type": "SQLi | XSS | SSRF | LFI | CMDi | etc",
      "success_indicator": "<string esperada na resposta HTTP se o ataque funcionar, ex: syntax error>"
    }
  ]
}
```

### Regras Rigorosas:
1. Você DEVE basear seus ataques EXCLUSIVAMENTE nos endpoints, rotas e parâmetros fornecidos no JSON de contexto (scan_results). É ESTRITAMENTE PROIBIDO inventar caminhos genéricos como /login ou /ping se eles não aparecerem nos dados.
2. Construa `data` condizente com o método e Content-Type (ex: json para `application/json`, querystring para `application/x-www-form-urlencoded`). Use a flag `"is_json"` corretamente.
3. O `success_indicator` deve ser o mais preciso possível para evitar falsos positivos na validação automatizada subsequente.
4. NENHUMA EXPLICAÇÃO. NENHUM COMENTÁRIO. APENAS O JSON VÁLIDO DE RETORNO.
"""


# ─── Classe Principal ───────────────────────────────────────────────────────

class GeminiAttacker:
    """
    Pipeline 6 — Motor Ofensivo Ativo via Google Gemini.

    Lê achados anteriores, pede para a IA gerar payloads e dispara requests.
    """

    def __init__(self, model_name: str = MODEL_NAME):
        self.api_key = os.getenv("GEMINI_API_KEY", "AIzaSyCQgAZkq1OLZvq7ISHCWM2-1hS_e8dIuxk")
        self.model_name = model_name
        self.client = None

        if not self.api_key:
            print_status(
                "⚠  GEMINI_API_KEY não definida. Pipeline 6 (Attacker) não poderá chamar a API.",
                "WARN",
            )
            return

        try:
            self.client = genai.Client(api_key=self.api_key)
            print_status(f"Gemini Attacker inicializado (modelo: {self.model_name})", "SUCCESS")
        except Exception as exc:
            print_status(f"Erro ao inicializar Gemini: {exc}", "ERROR")
            self.client = None

    # ── Método principal ────────────────────────────────────────────────

    def run_offensive_ai(self, scan_results: dict) -> dict:
        """
        Gera os ataques baseados nos resultados do scan, executa-os e retorna os confirmados.
        """
        if not self.client:
            print_status("Gemini Attacker indisponível (sem API key ou erro de init).", "ERROR")
            return {"confirmed_vulnerabilities": []}

        # Serializa os dados para enviar como contexto
        try:
            scan_json = json.dumps(scan_results, indent=2, ensure_ascii=False, default=str)
        except (TypeError, ValueError) as exc:
            print_status(f"Erro ao serializar scan_results: {exc}", "ERROR")
            return {"confirmed_vulnerabilities": []}

        # Trunca se for muito grande
        MAX_CHARS = 900_000
        if len(scan_json) > MAX_CHARS:
            print_status(f"JSON truncado de {len(scan_json):,} para {MAX_CHARS:,} chars.", "WARN")
            scan_json = scan_json[:MAX_CHARS]

        user_prompt = (
            "Gere payloads ofensivos baseados nos dados de scan a seguir. "
            "Siga as regras e retorne JSON conforme o schema exigido.\n\n"
            f"```json\n{scan_json}\n```"
        )

        print_status("Solicitando geração de payloads ao Gemini...", "INFO")

        try:
            config = types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.4,  # Um pouco mais de criatividade para payloads
                safety_settings=[
                    types.SafetySetting(category="HARM_CATEGORY_HATE_SPEECH",       threshold="BLOCK_NONE"),
                    types.SafetySetting(category="HARM_CATEGORY_HARASSMENT",        threshold="BLOCK_NONE"),
                    types.SafetySetting(category="HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold="BLOCK_NONE"),
                    types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT", threshold="BLOCK_NONE"),
                ],
                response_mime_type="application/json",
            )

            response = self.client.models.generate_content(
                model=self.model_name,
                contents=user_prompt,
                config=config,
            )

            if not response or not response.text:
                print_status("Gemini retornou resposta vazia.", "WARN")
                return {"confirmed_vulnerabilities": []}

            raw_text = response.text.strip()
            if raw_text.startswith("```"):
                raw_text = raw_text.split("\n", 1)[-1]
            if raw_text.endswith("```"):
                raw_text = raw_text.rsplit("```", 1)[0]

            payloads_data = json.loads(raw_text)
            attacks = payloads_data.get("targeted_attacks", [])

            if not attacks:
                print_status("Gemini não identificou oportunidades claras de ataque.", "WARN")
                return {"confirmed_vulnerabilities": []}

            print_status(f"Gemini sugeriu {len(attacks)} ataques direcionados. Executando...", "CRIT")
            
            confirmed_vulns = []

            for atk in attacks:
                url = atk.get("url")
                method = atk.get("method", "GET").upper()
                headers = atk.get("headers", {})
                data = atk.get("data")
                is_json = atk.get("is_json", False)
                vuln_type = atk.get("vulnerability_type", "Unknown")
                indicator = atk.get("success_indicator", "")

                if not url:
                    continue

                print_status(f"Atacando [{vuln_type}] em {url}...", "INFO")
                log.debug(f"Payload disparado: {data}")

                try:
                    # Executa a requisição real de forma segura (timeout e verify=False)
                    req_kwargs = {
                        "url": url,
                        "headers": headers,
                        "timeout": 5,
                        "verify": False
                    }
                    
                    if method == "GET":
                        # Em requisições GET com dados, enviamos via Query String (params)
                        if data and isinstance(data, dict):
                            req_kwargs["params"] = data
                        elif data and isinstance(data, str):
                            # Se a IA sugeriu string para GET, anexa ou manda via params hardcoded
                            req_kwargs["params"] = data
                        res = requests.get(**req_kwargs)
                    else:
                        if is_json:
                            # Se a string veio como json, converte para dict antes de usar json=
                            if isinstance(data, str):
                                try:
                                    parsed_data = json.loads(data)
                                except json.JSONDecodeError:
                                    parsed_data = data  # Envia a string crua se falhar no parse
                                req_kwargs["json"] = parsed_data
                            else:
                                req_kwargs["json"] = data
                        else:
                            req_kwargs["data"] = data
                            
                        if method == "POST":
                            res = requests.post(**req_kwargs)
                        elif method == "PUT":
                            res = requests.put(**req_kwargs)
                        elif method == "DELETE":
                            res = requests.delete(**req_kwargs)
                        else:
                            res = requests.request(method, **req_kwargs)

                    print(f"   [DEBUG] Status: {res.status_code} | Resumo: {res.text[:100].replace(chr(10), ' ').strip()}...")

                    # Valida se o success_indicator existe no corpo da resposta
                    if indicator and indicator.lower() in res.text.lower():
                        print_status(f"🔥 SUCESSO: Vulnerabilidade '{vuln_type}' confirmada!", "SUCCESS")
                        confirmed_vulns.append({
                            "vulnerability_type": vuln_type,
                            "url": url,
                            "method": method,
                            "payload_used": data,
                            "indicator_found": indicator
                        })
                    else:
                        log.debug(f"Falha ao confirmar {vuln_type}. Indicador não encontrado.")

                except requests.exceptions.RequestException as e:
                    print(f"   [DEBUG] Request error no alvo {url}: {e}")
                    log.debug(f"Request error no alvo {url}: {e}")

            print_status(f"Execução finalizada. {len(confirmed_vulns)} vulnerabilidades ativamente confirmadas.", "CRIT")
            return {"confirmed_vulnerabilities": confirmed_vulns}

        except json.JSONDecodeError as jde:
            print_status(f"Gemini retornou JSON inválido para payloads: {jde}", "ERROR")
            return {"confirmed_vulnerabilities": []}
        except Exception as exc:
            print_status(f"Erro na geração/execução de ataques do Gemini: {exc}", "ERROR")
            log.exception("Gemini Attacker API/Exec error")
            return {"confirmed_vulnerabilities": []}


# ─── Entrypoint de conveniência ─────────────────────────────────────────────

def run_offensive_ai(scan_results: dict) -> dict:
    """Entrypoint Pipeline 6 — Motor Ofensivo."""
    print_status("[PIPELINE 6] Gemini Active Attacker", "CRIT")
    attacker = GeminiAttacker()
    return attacker.run_offensive_ai(scan_results)

def run_gemini_overwatch(scan_results: dict) -> dict:
    """Fallback legadado para manter compatibilidade."""
    return run_offensive_ai(scan_results)


# ─── Pipeline API Security Analysis ────────────────────────────────────────

API_SECURITY_SYSTEM_PROMPT = """\
Você é um **Hacker Especialista em APIs** com mais de 15 anos de experiência em \
testes de intrusão focados em arquiteturas REST e GraphQL.

Você receberá o schema/especificação (Swagger/OpenAPI ou similar) de uma API.  
Seu objetivo é identificar a **falha arquitetural ou de lógica de negócio mais \
crítica** presente no schema — exemplos: IDOR, BOLA (Broken Object-Level Authorization), \
falhas de JWT (algorithm confusion, ausência de validação de assinatura, claims \
manipuláveis), Mass Assignment, SSRF via parâmetros, Excessive Data Exposure, \
falta de rate-limiting em endpoints sensíveis, etc.

Retorne EXCLUSIVAMENTE um JSON válido com DUAS chaves:

```json
{
  "insight": "<Explicação detalhada da falha arquitetural ou de lógica de negócio encontrada, incluindo o endpoint afetado e o impacto>",
  "payload": "<Comando CURL completo ou payload JSON exato, pronto para ser disparado contra a API para validar a falha>"
}
```

### Regras:
1. NÃO inclua texto fora do JSON. NENHUMA explicação adicional, NENHUM comentário.
2. O `payload` deve ser um comando CURL completo e funcional OU um payload JSON exato, \
   tecnicamente preciso para explorar a falha identificada.
3. Se o schema não apresentar falhas evidentes, ainda assim retorne o JSON, \
   colocando no `insight` a explicação de por que o schema parece seguro e no `payload` \
   um exemplo de teste de validação de segurança que poderia ser feito.
4. APENAS JSON VÁLIDO. NADA MAIS.
"""


def analyze_api_security(api_schema_text: str) -> dict:
    """
    Analisa o schema de uma API usando o Gemini como Hacker Especialista.

    Args:
        api_schema_text: Texto do schema/especificação da API (Swagger, OpenAPI, etc.)

    Returns:
        dict com as chaves 'insight' e 'payload', ou dict de erro.
    """
    api_key = os.getenv("GEMINI_API_KEY", "AIzaSyCQgAZkq1OLZvq7ISHCWM2-1hS_e8dIuxk")

    if not api_key:
        print_status("⚠  GEMINI_API_KEY não definida. Análise de API impossível.", "WARN")
        return {"error": "GEMINI_API_KEY não configurada", "insight": None, "payload": None}

    # Inicializa o cliente Gemini
    try:
        client = genai.Client(api_key=api_key)
    except Exception as exc:
        print_status(f"Erro ao inicializar Gemini para API Security: {exc}", "ERROR")
        return {"error": str(exc), "insight": None, "payload": None}

    # Monta o prompt do usuário com o schema
    user_prompt = (
        "Analise o schema de API abaixo como um Hacker Especialista. "
        "Encontre a falha mais crítica e retorne o JSON conforme instruído.\n\n"
        f"```json\n{api_schema_text}\n```"
    )

    print_status("Enviando schema para análise do Gemini (API Security)...", "INFO")

    try:
        config = types.GenerateContentConfig(
            system_instruction=API_SECURITY_SYSTEM_PROMPT,
            temperature=0.3,
            safety_settings=[
                types.SafetySetting(category="HARM_CATEGORY_HATE_SPEECH",       threshold="BLOCK_NONE"),
                types.SafetySetting(category="HARM_CATEGORY_HARASSMENT",        threshold="BLOCK_NONE"),
                types.SafetySetting(category="HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold="BLOCK_NONE"),
                types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT", threshold="BLOCK_NONE"),
            ],
            response_mime_type="application/json",
        )

        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=user_prompt,
            config=config,
        )

        if not response or not response.text:
            print_status("Gemini retornou resposta vazia na análise de API.", "WARN")
            return {"error": "Resposta vazia do Gemini", "insight": None, "payload": None}

        # ── Parse robusto do JSON retornado ──────────────────────────────
        raw_text = response.text.strip()

        # Remove cercas de markdown (```json ... ```)
        if raw_text.startswith("```"):
            raw_text = raw_text.split("\n", 1)[-1]
        if raw_text.endswith("```"):
            raw_text = raw_text.rsplit("```", 1)[0]
        raw_text = raw_text.strip()

        # Tenta o parse primário
        try:
            result = json.loads(raw_text)
        except json.JSONDecodeError:
            # Fallback: tenta extrair o primeiro bloco JSON válido do texto
            import re
            json_match = re.search(r'\{[\s\S]*\}', raw_text)
            if json_match:
                try:
                    result = json.loads(json_match.group())
                except json.JSONDecodeError as jde:
                    print_status(f"Falha total no parse do JSON do Gemini: {jde}", "ERROR")
                    log.error(f"Raw response:\n{raw_text[:500]}")
                    return {
                        "error": f"JSON inválido: {jde}",
                        "raw_response": raw_text[:1000],
                        "insight": None,
                        "payload": None,
                    }
            else:
                print_status("Nenhum bloco JSON encontrado na resposta do Gemini.", "ERROR")
                return {
                    "error": "Nenhum JSON encontrado na resposta",
                    "raw_response": raw_text[:1000],
                    "insight": None,
                    "payload": None,
                }

        # Valida presença das chaves obrigatórias
        insight = result.get("insight")
        payload = result.get("payload")

        if not insight or not payload:
            print_status("Gemini retornou JSON sem 'insight' e/ou 'payload'.", "WARN")
            return {
                "error": "Chaves 'insight' e/ou 'payload' ausentes",
                "raw_result": result,
                "insight": insight,
                "payload": payload,
            }

        print_status("Análise de API Security concluída com sucesso!", "SUCCESS")
        return {"insight": insight, "payload": payload}

    except json.JSONDecodeError as jde:
        print_status(f"Gemini retornou JSON inválido: {jde}", "ERROR")
        return {"error": f"JSON inválido: {jde}", "insight": None, "payload": None}
    except Exception as exc:
        print_status(f"Erro na análise de API Security do Gemini: {exc}", "ERROR")
        log.exception("Gemini API Security error")
        return {"error": str(exc), "insight": None, "payload": None}
