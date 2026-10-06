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
PreviSwit v3.0 — AI-Powered Pentest Framework
PreviSwit

Uso: python main.py http://target.com [--shodan KEY] [--vt KEY]
"""
import sys, json, re, argparse, requests, urllib3
from colorama import init, Fore, Style
from urllib.parse import urlparse
from config import Config
from core.banner import show_banner
from core.utils import print_status
from core.shared_context import SharedContext

# Pipelines
from modules.recon.recon import run_recon, PassiveRecon
from modules.recon.active import ActiveRecon
from modules.recon.subdomain_enum import SubdomainEnumerator

from modules.scanner.scanner import Scanner
from modules.scanner.waf_detector import WAFDetector
from modules.scanner.jwt_analyzer import JWTAnalyzer
from modules.scanner.graphql_tester import GraphQLTester
from modules.scanner.idor_tester import IDORTester
from modules.scanner.clickjacking import ClickjackingTester
from modules.scanner.osint_enricher import OSINTEnricher
from modules.scanner.ssl_analyzer import SSLAnalyzer
from modules.scanner.rate_limit_tester import RateLimitTester
from modules.scanner.api_fuzzer import APIFuzzer

from modules.aggressive.crawler import Crawler
from modules.aggressive.aggressive_engine import AggressiveEngine

from modules.plugins.loader import load_plugins
from modules.ai.ai_engine import run_ai

from reports.report import generate_pdf, generate_dashboard
from modules.attack.attack_engine import run_attack

init(autoreset=True)


def parse_args():
    p = argparse.ArgumentParser(description="PreviSwit v3 — AI-Powered Pentest")
    p.add_argument("target",          nargs="?", default=None, help="URL alvo (ex: http://site.com)")
    p.add_argument("--shodan",        default="", help="Shodan API Key (opcional)")
    p.add_argument("--vt",            default="", help="VirusTotal API Key (opcional)")
    p.add_argument("--pipeline",      default="all", choices=["1","2","3","4","6","all"],
                   help="Pipeline: 1=tradicional, 2=agressivo, 3=IA, 4=ataque, 6=Gemini Attacker, all=todos")
    p.add_argument("--no-aggressive", action="store_true", help="Pula pipeline agressivo")
    p.add_argument("--attack",        action="store_true",
                   help="Força Pipeline 4 (ataque) mesmo sem --pipeline 4 ou all")
    p.add_argument("--api-security",  type=str, nargs="?", const="__mock__", default=None,
                   help="Pipeline 7: caminho local ou URL do schema (ex: schemas/swagger.json ou http://api.com/docs.json). Sem argumento = mock.")
    p.add_argument("--target-url",    type=str, default=None,
                   help="URL base do alvo para validação DAST (ex: http://localhost:3000). Usado com --api-security.")
    args = p.parse_args()

    # target é obrigatório exceto quando --api-security é usado
    if not args.api_security and args.target is None:
        p.error("o argumento 'target' é obrigatório (exceto com --api-security)")

    return args


def save_results(full_results: dict, target: str) -> dict:
    """Salva relatórios (JSON, PDF, HTML) e retorna os caminhos gerados."""
    Config.ensure_dirs()
    base = urlparse(target).netloc.replace(".", "_").replace(":", "_") or "target"

    json_file = f"{Config.REPORT_DIR}/{base}_report.json"
    pdf_file  = f"{Config.REPORT_DIR}/{base}_report.pdf"
    html_file = f"{Config.REPORT_DIR}/{base}_dashboard.html"

    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(full_results, f, indent=2, ensure_ascii=False, default=str)

    generate_pdf(full_results, pdf_file)
    generate_dashboard(full_results, html_file)

    print_status(f"JSON      → {json_file}", "SUCCESS")
    print_status(f"PDF       → {pdf_file}", "SUCCESS")
    print_status(f"Dashboard → {html_file}", "SUCCESS")

    return {"json": json_file, "pdf": pdf_file, "html": html_file}


def run_scan(target: str, pipeline: str = "all", shodan: str = "",
             vt: str = "", no_aggressive: bool = False,
             attack: bool = False) -> tuple[dict, dict]:
    """
    Executa o pipeline PreviSwit de forma programática.

    Args:
        target:         URL alvo (ex: http://site.com)
        pipeline:       "1", "2", "3", "4", "6" ou "all"
        shodan:         Shodan API key (opcional)
        vt:             VirusTotal API key (opcional)
        no_aggressive:  Pula pipeline 2 se True
        attack:         Força pipeline 4 se True

    Returns:
        (full_results, report_paths) — dicionário com todos os achados
        e dicionário com os caminhos dos relatórios gerados.
    """
    if not target.startswith("http"):
        target = "http://" + target

    Config.ensure_dirs()
    context         = SharedContext()
    context.target  = target
    context.init_db()
    context.add_url(target)

    domain = urlparse(target).netloc

    print_status(f"Alvo: {target}", "CRIT")
    print_status(f"Pipeline: {pipeline}", "INFO")

    full = {"target": target}

    # ══════════════════════════════════════════════════════
    # PIPELINE 1 — TRADICIONAL: Recon → Scanner → Relatório
    # ══════════════════════════════════════════════════════
    if pipeline in ("1", "all"):
        print_status("", "INFO")
        print_status("━━━ PIPELINE 1: TRADICIONAL ━━━━━━━━━━━━━━━━━━━━━━━━", "CRIT")

        print_status("[1/6] Recon Passivo", "INFO")
        pr = PassiveRecon(target)
        full["passive"] = pr.execute_all()

        print_status("[2/6] Recon Ativo (Nmap + Gobuster)", "INFO")
        ar = ActiveRecon(target)
        full["active"] = ar.execute_all()

        print_status("[3/6] SSL/TLS Analysis", "INFO")
        ssl_a = SSLAnalyzer(target, context)
        full["ssl"] = ssl_a.analyze()

        print_status("[4/6] Subdomain Enumeration", "INFO")
        sub = SubdomainEnumerator(domain, context)
        full["subdomains"] = sub.run()

        print_status("[5/6] OSINT Enrichment", "INFO")
        osint = OSINTEnricher(target, shodan, vt)
        full["osint"] = osint.run()

        print_status("[6/6] Scanner (Nikto + CORS + Open Redirect)", "INFO")
        sc = Scanner(target)
        full["scanner"] = sc.execute_all()

    # ══════════════════════════════════════════════════════
    # PIPELINE 2 — AGRESSIVO: Discovery → Crawler → Plugins
    # ══════════════════════════════════════════════════════
    if pipeline in ("2", "all") and not no_aggressive:
        print_status("", "INFO")
        print_status("━━━ PIPELINE 2: AGRESSIVO ━━━━━━━━━━━━━━━━━━━━━━━━━━", "CRIT")

        print_status("[1/8] WAF Fingerprinting", "INFO")
        waf = WAFDetector(target)
        full["waf"] = waf.probe()

        print_status("[2/8] Crawler profundo", "INFO")
        crawler = Crawler(target, context=context)
        pages   = crawler.crawl()
        context.add_pages(pages)
        full["crawled_pages"] = len(pages)

        print_status("[3/8] Motor Agressivo (JS endpoints + Path Traversal + Paths sensíveis)", "INFO")
        agg = AggressiveEngine(target, context)
        full["aggressive"] = agg.run(pages)

        print_status("[4/8] API Fuzzer", "INFO")
        api_fuzz = APIFuzzer(target, context)
        full["api_fuzzer"] = api_fuzz.run(pages)

        print_status("[5/8] GraphQL Tester", "INFO")
        gql = GraphQLTester(target, context)
        full["graphql"] = gql.run()

        print_status("[6/8] Clickjacking Tester", "INFO")
        cj = ClickjackingTester(target, context)
        full["clickjacking"] = cj.test()

        print_status("[7/8] Rate Limit Tester", "INFO")
        rl = RateLimitTester(target, context)
        full["rate_limit"] = rl.test()

        print_status("[8/8] Plugins", "INFO")
        plugins = load_plugins()
        plugin_findings = []
        from core.utils import safe_request
        r_main = safe_request(target)
        if r_main:
            for plugin in plugins:
                result = plugin.run(target, r_main)
                if result:
                    plugin_findings.append(result)
                    context.add_finding({**result, "source": f"Plugin:{plugin.name}"})
        full["plugins"] = plugin_findings

    # ══════════════════════════════════════════════════════
    # PIPELINE 3 — IA: Análise global → Priorização → Insights
    # ══════════════════════════════════════════════════════
    if pipeline in ("3", "all"):
        print_status("", "INFO")
        print_status("━━━ PIPELINE 3: IA ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "CRIT")

        pages = context.pages or []

        print_status("[1/5] JWT Analyzer", "INFO")
        jwt = JWTAnalyzer()
        full["jwt"] = jwt.scan_pages(pages)

        print_status("[2/5] IDOR Tester", "INFO")
        idor = IDORTester(target, context)
        full["idor"] = idor.test(pages)

        print_status("[3/5] CVE Lookup por tecnologia", "INFO")
        techs_so_far = full.get("scanner", {}).get("technologies", [])

        print_status("[4/5] AI Engine (Secrets + Smart Analysis + Exploiter + Priorização)", "INFO")
        active_headers = full.get("active", {}).get("headers", {})
        ai_results = run_ai(target, context, pages, active_headers)

        full["technologies"]       = ai_results.get("technologies", [])
        full["secrets"]            = ai_results.get("secrets", [])
        full["smart_analysis"]     = ai_results.get("smart_analysis", [])
        full["exploitation"]       = ai_results.get("exploitation", [])
        full["ai_insights"]        = ai_results.get("insights", [])
        full["ai_top_issues"]      = ai_results.get("top_issues", [])
        full["findings_prioritized"] = ai_results.get("prioritized", [])

        # CVEs por tech detectada
        if full["technologies"]:
            sc2 = Scanner(target)
            full["cve_matches"] = sc2.cve_lookup(full["technologies"]) if hasattr(sc2,"cve_lookup") else []
        else:
            full["cve_matches"] = []

        print_status("[5/5] Gerando Relatórios (PDF + Dashboard HTML)", "INFO")

    # ══════════════════════════════════════════════════════
    # PIPELINE 4 — ATTACK: Exploração automática baseada nos findings
    # ══════════════════════════════════════════════════════
    if pipeline in ("4", "all") or attack:
        print_status("", "INFO")
        print_status("━━━ PIPELINE 4: ATAQUE AUTOMÁTICO ━━━━━━━━━━━━━━━━━━━━", "CRIT")
        print_status("ATENÇÃO: Use apenas em ambientes autorizados!", "WARN")

        # Garante que findings estejam disponíveis antes do ataque
        if "findings_prioritized" not in full:
            from modules.ai.risk_engine import RiskEngine
            risk = RiskEngine()
            full["findings_prioritized"] = risk.prioritize(context.all_findings())[:60]

        attack_results = run_attack(target, full, context)
        full["attack"] = attack_results
        full["attack_insights"] = attack_results.get("insights", [])
        full["attack_summary"]  = attack_results.get("summary", {})

    # ══════════════════════════════════════════════════════
    # PIPELINE 6 — GEMINI ATTACKER: Teste ofensivo (Pipeline 6)
    # ══════════════════════════════════════════════════════
    if pipeline in ("6", "all"):
        print_status("", "INFO")
        print_status("━━━ GEMINI ACTIVE ATTACKER ━━━━━━━━━━━━━━━━━━━━━━━━━", "CRIT")

        from modules.ai_gemini.gemini_pipeline import run_offensive_ai
        gemini_result = run_offensive_ai(full)
        full["gemini_attacker"] = gemini_result

        # Imprime resultados das confirmações
        confirmed = gemini_result.get("confirmed_vulnerabilities", [])
        print_status(
            f"Gemini Attacker: {len(confirmed)} vulnerabilidades exploradas com sucesso.",
            "SUCCESS" if len(confirmed) > 0 else "INFO",
        )
        
        if confirmed:
            for i, atk in enumerate(confirmed, 1):
                vuln = atk.get('vulnerability_type', 'N/A')
                url = atk.get('url', 'N/A')
                print_status(f"  {i}. [CONFIRMADA] {vuln} em {url}", "CRIT")

    # ══════════════════════════════════════════════════════
    # RELATÓRIO FINAL
    # ══════════════════════════════════════════════════════
    print_status("", "INFO")
    print_status("━━━ GERANDO RELATÓRIOS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "CRIT")

    # Garante que findings_prioritized existe
    if "findings_prioritized" not in full:
        from modules.ai.risk_engine import RiskEngine
        risk = RiskEngine()
        full["findings_prioritized"] = risk.prioritize(context.all_findings())[:60]

    if "secrets" not in full:
        full["secrets"] = []
    if "technologies" not in full:
        full["technologies"] = []
    if "ai_insights" not in full:
        full["ai_insights"] = []
    if "ai_top_issues" not in full:
        full["ai_top_issues"] = []
    if "cve_matches" not in full:
        full["cve_matches"] = []

    report_paths = save_results(full, target)

    # Resumo final
    total = len(full["findings_prioritized"])
    crit  = sum(1 for f in full["findings_prioritized"] if f.get("severity","").upper()=="CRITICAL")
    high  = sum(1 for f in full["findings_prioritized"] if f.get("severity","").upper()=="HIGH")

    print_status("", "INFO")
    print_status(f"VARREDURA FINALIZADA — {total} findings ({crit} críticos, {high} altos)", "SUCCESS")
    if full.get("ai_insights"):
        print_status("INSIGHTS DA IA:", "WARN")
        for ins in full["ai_insights"]:
            print_status(ins, "WARN")

    return full, report_paths



# ══════════════════════════════════════════════════════════════════════════════
# PIPELINE 7 — API SECURITY ANALYSIS (Gemini Hacker Especialista)
# ══════════════════════════════════════════════════════════════════════════════

MOCK_SWAGGER_SCHEMA = json.dumps({
    "openapi": "3.0.0",
    "info": {
        "title": "FinBank API",
        "version": "1.2.0",
        "description": "API interna do FinBank para gestão de contas e transações."
    },
    "servers": [
        {"url": "https://api.finbank.local/v1"}
    ],
    "paths": {
        "/users/{user_id}/profile": {
            "get": {
                "summary": "Retorna perfil do usuário",
                "parameters": [
                    {"name": "user_id", "in": "path", "required": True, "schema": {"type": "integer"}}
                ],
                "security": [],
                "responses": {
                    "200": {
                        "description": "Dados do perfil",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "id": {"type": "integer"},
                                        "name": {"type": "string"},
                                        "email": {"type": "string"},
                                        "cpf": {"type": "string"},
                                        "balance": {"type": "number"}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "/users/{user_id}/transactions": {
            "get": {
                "summary": "Lista transações do usuário",
                "parameters": [
                    {"name": "user_id", "in": "path", "required": True, "schema": {"type": "integer"}},
                    {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 50}}
                ],
                "security": [],
                "responses": {
                    "200": {"description": "Lista de transações"}
                }
            }
        },
        "/transfer": {
            "post": {
                "summary": "Realiza transferência entre contas",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "from_account": {"type": "integer"},
                                    "to_account": {"type": "integer"},
                                    "amount": {"type": "number"},
                                    "note": {"type": "string"}
                                },
                                "required": ["from_account", "to_account", "amount"]
                            }
                        }
                    }
                },
                "security": [{"bearerAuth": []}],
                "responses": {
                    "200": {"description": "Transferência realizada"}
                }
            }
        },
        "/auth/login": {
            "post": {
                "summary": "Autenticação via JWT",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "email": {"type": "string"},
                                    "password": {"type": "string"}
                                },
                                "required": ["email", "password"]
                            }
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "Token JWT retornado",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "token": {"type": "string"},
                                        "expires_in": {"type": "integer"}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "/admin/users": {
            "get": {
                "summary": "Lista todos os usuários (admin)",
                "security": [],
                "responses": {
                    "200": {"description": "Lista de todos os usuários"}
                }
            },
            "delete": {
                "summary": "Deleta um usuário pelo ID",
                "parameters": [
                    {"name": "id", "in": "query", "required": True, "schema": {"type": "integer"}}
                ],
                "security": [],
                "responses": {
                    "200": {"description": "Usuário deletado"}
                }
            }
        }
    },
    "components": {
        "securitySchemes": {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT"
            }
        }
    }
}, indent=2, ensure_ascii=False)


def _load_schema(source: str) -> str:
    """
    Carrega o conteúdo de um schema de API a partir de um arquivo local ou URL.

    Args:
        source: Caminho de arquivo local ou URL (http/https).

    Returns:
        Conteúdo do schema como string.

    Raises:
        FileNotFoundError: Se o arquivo local não existir.
        requests.RequestException: Se a requisição HTTP falhar.
        ValueError: Se a resposta HTTP não for 2xx.
    """
    if source.startswith(("http://", "https://")):
        print_status(f"Baixando schema de: {source}", "INFO")
        resp = requests.get(source, timeout=15, verify=False)
        if resp.status_code >= 400:
            raise ValueError(
                f"HTTP {resp.status_code} ao baixar schema de {source}"
            )
        print_status(f"Download OK — {len(resp.text):,} caracteres recebidos.", "SUCCESS")
        return resp.text

    # Arquivo local
    import os
    path = os.path.abspath(source)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Arquivo não encontrado: {path}")

    print_status(f"Lendo schema local: {path}", "INFO")
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    print_status(f"Arquivo lido — {len(content):,} caracteres.", "SUCCESS")
    return content


# ─── Indicadores de sucesso de exploit ──────────────────────────────────────
# Padrões na resposta HTTP que indicam que o ataque funcionou
_EXPLOIT_INDICATORS = [
    # SQL Injection
    "sql syntax", "sqlite_version", "mysql", "pg_catalog", "ora-",
    "syntax error", "unclosed quotation", "unterminated string",
    "sqlstate", "jdbc", "odbc", "sql error",
    # Data Leaks / IDOR
    "password", "passwd", "secret", "token", "credit",
    "ssn", "cpf", "email", "balance",
    # Error-based info disclosure
    "stack trace", "traceback", "exception", "internal server error",
    "debug", "verbose",
    # Authentication bypass
    "authentication", "unauthenticated", "admin",
]


def _parse_curl(curl_cmd: str, target_url: str = None) -> dict:
    """
    Converte um comando CURL em parâmetros para requests.

    Args:
        curl_cmd:   Comando CURL do Gemini.
        target_url: URL base do alvo real (para substituir hosts do schema).

    Returns:
        dict com: method, url, headers, data, is_json
    """
    result = {"method": "GET", "url": "", "headers": {}, "data": None, "is_json": False}

    # Extrai o método (-X METHOD)
    method_match = re.search(r'-X\s+(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)', curl_cmd, re.IGNORECASE)
    if method_match:
        result["method"] = method_match.group(1).upper()

    # Se não tem -X mas tem -d/--data, assume POST
    if not method_match and re.search(r'(?:-d|--data)', curl_cmd):
        result["method"] = "POST"

    # Extrai a URL (primeira coisa que parece URL ou string entre aspas após curl)
    url_match = re.search(r'["\']?(https?://[^\s"\'\']+)["\']?', curl_cmd)
    if url_match:
        raw_url = url_match.group(1)

        # Se target_url fornecido, substitui o host/base do CURL pelo alvo real
        if target_url:
            parsed_curl = urlparse(raw_url)
            parsed_target = urlparse(target_url)
            # Preserva o path+query do CURL mas troca scheme+host pelo target
            raw_url = f"{parsed_target.scheme}://{parsed_target.netloc}{parsed_curl.path}"
            if parsed_curl.query:
                raw_url += f"?{parsed_curl.query}"

        result["url"] = raw_url

    # Extrai headers (-H 'Key: Value')
    for hdr in re.finditer(r"-H\s+['\"]([^'\"]+)['\"]", curl_cmd):
        parts = hdr.group(1).split(":", 1)
        if len(parts) == 2:
            result["headers"][parts[0].strip()] = parts[1].strip()

    # Extrai data (-d / --data / --data-raw)
    data_match = re.search(r'(?:-d|--data|--data-raw)\s+["\'](.+?)["\']', curl_cmd, re.DOTALL)
    if data_match:
        raw_data = data_match.group(1)
        # Tenta parsear como JSON
        try:
            result["data"] = json.loads(raw_data)
            result["is_json"] = True
        except json.JSONDecodeError:
            result["data"] = raw_data
            result["is_json"] = False

    return result


def validate_api_vulnerability(target_url: str, gemini_payload: str) -> dict:
    """
    Executa o payload gerado pelo Gemini contra o alvo real (DAST).

    Traduz o CURL/payload em uma requisição requests, dispara contra o
    target_url, e analisa a resposta para verificar se a vulnerabilidade
    é explorável de fato.

    Args:
        target_url:     URL base do alvo (ex: http://localhost:3000)
        gemini_payload: Comando CURL ou payload texto gerado pelo Gemini.

    Returns:
        dict com: validated (bool), status_code, evidence, url, method
    """
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    print_status("", "INFO")
    print_status("━━━ DAST: VALIDAÇÃO DO EXPLOIT ━━━━━━━━━━━━━━━━━━━━━━━━━", "CRIT")
    print_status(f"Alvo: {target_url}", "INFO")

    # ── Parseia o CURL do Gemini ─────────────────────────────────────────
    parsed = _parse_curl(gemini_payload, target_url)

    if not parsed["url"]:
        print_status("❌ Não foi possível extrair URL do payload do Gemini.", "ERROR")
        return {"validated": False, "error": "URL não encontrada no payload"}

    method  = parsed["method"]
    url     = parsed["url"]
    headers = parsed["headers"]
    data    = parsed["data"]
    is_json = parsed["is_json"]

    print_status(f"Método: {method}", "INFO")
    print_status(f"URL:    {url}", "INFO")
    if headers:
        print_status(f"Headers: {json.dumps(headers, ensure_ascii=False)}", "INFO")
    if data:
        preview = json.dumps(data, ensure_ascii=False) if isinstance(data, dict) else str(data)
        print_status(f"Data:   {preview[:200]}", "INFO")

    print_status("Disparando requisição...", "WARN")

    # ── Executa a requisição ─────────────────────────────────────────────
    try:
        req_kwargs = {
            "url": url,
            "headers": headers,
            "timeout": 10,
            "verify": False,
            "allow_redirects": True,
        }

        if method in ("POST", "PUT", "PATCH") and data:
            if is_json:
                req_kwargs["json"] = data
            else:
                req_kwargs["data"] = data
        elif method == "GET" and data and isinstance(data, dict):
            req_kwargs["params"] = data

        response = requests.request(method, **req_kwargs)

    except requests.exceptions.ConnectionError:
        print(f"\n{Fore.RED}[✗] ERRO DE CONEXÃO: O alvo {target_url} está offline ou inacessível.{Style.RESET_ALL}\n")
        return {"validated": False, "error": "Conexão recusada", "url": url}
    except requests.exceptions.Timeout:
        print(f"\n{Fore.RED}[✗] TIMEOUT: O alvo não respondeu a tempo.{Style.RESET_ALL}\n")
        return {"validated": False, "error": "Timeout", "url": url}
    except requests.exceptions.RequestException as e:
        print(f"\n{Fore.RED}[✗] ERRO HTTP: {e}{Style.RESET_ALL}\n")
        return {"validated": False, "error": str(e), "url": url}

    # ── Analisa a resposta ───────────────────────────────────────────────
    status  = response.status_code
    body    = response.text.lower()
    body_preview = response.text[:500]

    print_status(f"Status HTTP: {status}", "INFO")
    print_status(f"Tamanho da resposta: {len(response.text):,} caracteres", "INFO")

    # Verifica indicadores de exploit na resposta
    found_indicators = [ind for ind in _EXPLOIT_INDICATORS if ind in body]

    # Condições para considerar o ataque validado:
    #   1. Status 200 (ou 201/301/302) E pelo menos 1 indicador encontrado
    #   2. Status 500 com indicadores de SQL/error disclosure
    validated = False
    evidence  = []

    if status in (200, 201) and found_indicators:
        validated = True
        evidence  = found_indicators
    elif status == 500 and any(i in body for i in ["sql", "syntax", "trace", "exception"]):
        validated = True
        evidence  = [i for i in ["sql", "syntax", "trace", "exception"] if i in body]
    elif status in (200, 201) and len(response.text) > 50:
        # Status 200 com corpo substancial — possível data leak mesmo sem indicadores claros
        validated = True
        evidence  = ["response_with_data (200 OK com corpo substancial)"]

    # ── Output colorido ─────────────────────────────────────────────────
    print()
    if validated:
        print(f"{Fore.RED}{'═' * 60}{Style.RESET_ALL}")
        print(f"{Fore.RED}  🔥  VULNERABILIDADE CONFIRMADA!{Style.RESET_ALL}")
        print(f"{Fore.RED}{'═' * 60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}  ✅  Ataque foi validado com sucesso!{Style.RESET_ALL}")
        print(f"{Fore.GREEN}  ├─ URL:        {url}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}  ├─ Método:     {method}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}  ├─ Status:     {status}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}  ├─ Evidências: {', '.join(evidence)}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}  └─ Preview:{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}     {body_preview[:300]}{Style.RESET_ALL}")
        print(f"{Fore.RED}{'═' * 60}{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}{'═' * 60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}  🛡️  API ESTÁ PROTEGIDA{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'═' * 60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  ├─ URL:    {url}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  ├─ Status: {status}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  └─ O payload não produziu evidências de exploração.{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'═' * 60}{Style.RESET_ALL}")
    print()

    return {
        "validated": validated,
        "status_code": status,
        "evidence": evidence,
        "url": url,
        "method": method,
        "response_preview": body_preview[:500],
    }


def run_api_security_analysis(source: str = None, target_url: str = None):
    """
    Pipeline 7 — Orquestrador de Análise de Segurança de API via Gemini.

    Lê o schema de uma API real (de arquivo local ou URL), envia para o
    Gemini como Hacker Especialista, imprime o resultado (Insight + Payload),
    e opcionalmente dispara o exploit contra o alvo (DAST).

    Args:
        source:     Caminho de arquivo local, URL do schema, ou None/"__mock__"
                    para usar o schema mockado embutido.
        target_url: URL base do alvo para validação DAST (ex: http://localhost:3000).
                    Se None, a validação DAST é pulada.
    """
    from modules.ai_gemini.gemini_pipeline import analyze_api_security

    print_status("", "INFO")
    print_status("━━━ PIPELINE 7: API SECURITY ANALYSIS (Gemini Hacker) ━━━", "CRIT")

    # ── Carrega o schema ─────────────────────────────────────────────────
    if source is None or source == "__mock__":
        print_status("Nenhuma fonte informada — usando schema mockado (FinBank API).", "WARN")
        schema_text = MOCK_SWAGGER_SCHEMA
    else:
        try:
            schema_text = _load_schema(source)
        except FileNotFoundError as e:
            print_status(f"❌ Arquivo não encontrado: {e}", "ERROR")
            return {"error": str(e), "insight": None, "payload": None}
        except requests.exceptions.ConnectionError as e:
            print_status(f"❌ Erro de conexão ao baixar schema: {e}", "ERROR")
            return {"error": f"Erro de conexão: {e}", "insight": None, "payload": None}
        except requests.exceptions.Timeout as e:
            print_status(f"❌ Timeout ao baixar schema: {e}", "ERROR")
            return {"error": f"Timeout: {e}", "insight": None, "payload": None}
        except requests.exceptions.RequestException as e:
            print_status(f"❌ Erro HTTP ao baixar schema: {e}", "ERROR")
            return {"error": f"Erro HTTP: {e}", "insight": None, "payload": None}
        except ValueError as e:
            print_status(f"❌ {e}", "ERROR")
            return {"error": str(e), "insight": None, "payload": None}
        except Exception as e:
            print_status(f"❌ Erro inesperado ao carregar schema: {e}", "ERROR")
            return {"error": str(e), "insight": None, "payload": None}

    print_status(f"Schema carregado: {len(schema_text):,} caracteres.", "INFO")

    # ── Envia para o Gemini ──────────────────────────────────────────────
    gemini_api_key = os.getenv("GEMINI_API_KEY", "")
    if not gemini_api_key:
        print_status("⚠  GEMINI_API_KEY não definida. Análise falhou.", "ERROR")
        return {"error": "GEMINI_API_KEY ausente", "insight": None, "payload": None}

    result = analyze_api_security(schema_text, api_key=gemini_api_key)

    # ── Exibe resultado no terminal ──────────────────────────────────────
    print_status("", "INFO")

    if result.get("error"):
        print_status(f"⚠  Erro na análise: {result['error']}", "ERROR")
        if result.get("raw_response"):
            print_status(f"Resposta bruta (truncada): {result['raw_response'][:300]}", "WARN")
        return result

    print_status("═══════════════════════════════════════════════════════", "CRIT")
    print_status("  🔍  INSIGHT (Falha Identificada):", "CRIT")
    print_status("═══════════════════════════════════════════════════════", "CRIT")
    print(f"\n{result['insight']}\n")

    print_status("═══════════════════════════════════════════════════════", "CRIT")
    print_status("  💣  PAYLOAD (Comando de Validação):", "CRIT")
    print_status("═══════════════════════════════════════════════════════", "CRIT")
    print(f"\n{result['payload']}\n")

    # ── DAST: Validação do exploit contra o alvo real ────────────────────
    if target_url:
        dast_result = validate_api_vulnerability(target_url, result["payload"])
        result["dast"] = dast_result
    else:
        print_status("", "INFO")
        print_status("ℹ️  Nenhum --target-url fornecido. Pulando validação DAST.", "WARN")
        print_status("   Use: python main.py --api-security <schema> --target-url http://alvo:porta", "WARN")

    print_status("Análise de API Security finalizada.", "SUCCESS")
    return result


def main():
    show_banner()
    args   = parse_args()

    # Se --api-security foi passado, roda apenas a análise de API e sai
    if args.api_security is not None:
        run_api_security_analysis(args.api_security, target_url=args.target_url)
        return

    run_scan(
        target=args.target,
        pipeline=args.pipeline,
        shodan=args.shodan,
        vt=args.vt,
        no_aggressive=args.no_aggressive,
        attack=args.attack,
    )


if __name__ == "__main__":
    main()
