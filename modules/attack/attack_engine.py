"""
attack/attack_engine.py — Pipeline 4: Orquestrador central do ataque.

Recebe o full_results dos pipelines 1–3 e:
  1. Prioriza quais ataques rodar com base nos findings
  2. Executa SQLiAttacker, XSSAttacker, PathAttacker, AuthAttacker
  3. Consolida tudo num dict attack_results
  4. Gera insights do ataque (o que foi comprometido de fato)
"""
from core.utils import print_status
from modules.attack.sqli_attacker import SQLiAttacker
from modules.attack.xss_attacker  import XSSAttacker
from modules.attack.path_attacker  import PathAttacker
from modules.attack.auth_attacker  import AuthAttacker
from modules.attack.juice_attacker import JuiceAttacker


class AttackEngine:
    """
    Orquestrador do Pipeline 4.
    Decide quais atacantes ativar com base nos findings priorizados.
    """

    def __init__(self, target: str, full_results: dict, context=None):
        self.target       = target
        self.full         = full_results
        self.context      = context
        self.findings     = full_results.get("findings_prioritized", [])
        self.pages        = context.pages if context else []
        self.results      = {
            "sqli":    {},
            "xss":     {},
            "path":    {},
            "auth":    {},
            "juice":   {},
            "summary": {},
            "insights": [],
        }

    def _log(self, msg, level="INFO"):
        print_status(f"[Attack] {msg}", level)

    # ── Decide prioridade dos módulos ─────────────────────────────────────────

    def _should_run(self, keywords: list) -> bool:
        return any(
            any(kw in (f.get("issue","") + f.get("type","")).lower()
                for kw in keywords)
            for f in self.findings
        )

    # ── Gera insights pós-ataque ──────────────────────────────────────────────

    def _build_insights(self):
        insights = []
        sqli = self.results["sqli"]
        xss  = self.results["xss"]
        path = self.results["path"]
        auth = self.results["auth"]

        if sqli.get("db_version"):
            insights.append(
                f"💣 Banco de dados comprometido — versão: {sqli['db_version']}. "
                "Dump de dados sensíveis pode ser possível."
            )
        if sqli.get("dumped_data"):
            total = sum(d.get("total",0) for d in sqli["dumped_data"])
            tables = [d["table"] for d in sqli["dumped_data"]]
            insights.append(
                f"🗄️  {total} registro(s) extraído(s) das tabelas: {', '.join(tables)}."
            )
        if sqli.get("auth_bypassed"):
            insights.append(
                f"🔓 Auth bypass por SQLi confirmado em "
                f"{len(sqli['auth_bypassed'])} endpoint(s)."
            )
        if xss.get("confirmed_xss") or xss.get("bypass_xss"):
            n = len(xss.get("confirmed_xss",[])) + len(xss.get("bypass_xss",[]))
            insights.append(
                f"🎯 {n} XSS confirmado(s) — possível roubo de sessão/cookie."
            )
        if xss.get("dom_xss"):
            insights.append(
                f"⚡ DOM XSS detectado em {len(xss['dom_xss'])} arquivo(s) JS — "
                "investigar sinks e fontes identificados."
            )
        if path.get("files_read"):
            files = [f["file"] for f in path["files_read"]]
            insights.append(
                f"📁 Arquivos do sistema lidos via LFI: {', '.join(files)}."
            )
        if path.get("app_configs"):
            insights.append(
                f"⚙️  {len(path['app_configs'])} arquivo(s) de configuração da "
                "aplicação acessados — possível exposição de credenciais."
            )
        if path.get("log_poison"):
            insights.append(
                "☠️  Log Poisoning viável — PHP injetado no log. "
                "Escalonamento para RCE possível via LFI+Log."
            )
        if auth.get("valid_credentials"):
            creds = auth["valid_credentials"]
            insights.append(
                f"🔑 {len(creds)} credencial(ais) válida(s) encontrada(s): "
                + ", ".join(f"{c['username']}:{c['password']}" for c in creds[:3])
            )
        if auth.get("user_enum"):
            insights.append(
                f"👤 {len(auth['user_enum'])} usuário(s) enumerado(s) via "
                "diferença de resposta."
            )

        juice = self.results.get("juice", {})
        if juice.get("advanced_xss"):
            insights.append(f"💥 XSS Avançado detectado em {len(juice['advanced_xss'])} vetor(es) específico(s).")
        if juice.get("sensitive_files"):
            insights.append(f"📄 Arquivos Confidenciais/Métricas acessados: {len(juice['sensitive_files'])} arquivo(s).")
        if juice.get("business_logic"):
            insights.append(f"🧠 Vulnerabilidades de Lógica de Negócio: {', '.join(juice['business_logic'])}.")
        if juice.get("insecure_deserialization"):
            insights.append(f"🔥 Vulnerabilidades de Insecure Deserialization: {', '.join(juice['insecure_deserialization'])}.")

        if not insights:
            insights.append(
                "ℹ️  Nenhum comprometimento direto confirmado nesta sessão — "
                "alvos podem ter proteções adicionais."
            )
        self.results["insights"] = insights

    # ── Sumário consolidado ───────────────────────────────────────────────────

    def _build_summary(self):
        sqli = self.results["sqli"]
        xss  = self.results["xss"]
        path = self.results["path"]
        auth = self.results["auth"]

        self.results["summary"] = {
            "db_version":       sqli.get("db_version"),
            "tables_found":     len(sqli.get("tables",[])),
            "records_dumped":   sum(d.get("total",0) for d in sqli.get("dumped_data",[])),
            "auth_bypassed":    len(sqli.get("auth_bypassed",[])),
            "xss_confirmed":    len(xss.get("confirmed_xss",[])) + len(xss.get("bypass_xss",[])),
            "dom_xss":          len(xss.get("dom_xss",[])),
            "files_read":       len(path.get("files_read",[])),
            "configs_exposed":  len(path.get("app_configs",[])),
            "log_poison":       path.get("log_poison", False),
            "valid_creds":      len(auth.get("valid_credentials",[])),
            "users_enumerated": len(auth.get("user_enum",[])),
            "juice_adv_xss":    len(self.results.get("juice", {}).get("advanced_xss", [])),
            "juice_logic":      len(self.results.get("juice", {}).get("business_logic", [])),
        }

    # ── Run ───────────────────────────────────────────────────────────────────

    def run(self) -> dict:
        print_status("[PIPELINE 4] Attack Engine — iniciando exploração", "CRIT")

        # ── SQL Injection ──────────────────────────────────────────────────────
        if self._should_run(["sql", "sqli", "injection"]):
            print_status("[1/4] SQLi Attacker", "INFO")
            attacker = SQLiAttacker(self.target, self.findings, self.context)
            self.results["sqli"] = attacker.run()
        else:
            print_status("[1/4] SQLi — nenhum finding elegível, pulando.", "WARN")

        # ── XSS ───────────────────────────────────────────────────────────────
        if self._should_run(["xss", "cross-site", "script"]):
            print_status("[2/4] XSS Attacker", "INFO")
            attacker = XSSAttacker(self.target, self.findings, self.pages)
            self.results["xss"] = attacker.run()
        else:
            print_status("[2/4] XSS — nenhum finding elegível, pulando.", "WARN")

        # ── Path Traversal / LFI ──────────────────────────────────────────────
        if self._should_run(["traversal", "lfi", "path", "inclusion", "sensitive"]):
            print_status("[3/4] Path/LFI Attacker", "INFO")
            attacker = PathAttacker(self.target, self.findings, self.context)
            self.results["path"] = attacker.run()
        else:
            print_status("[3/4] Path/LFI — nenhum finding elegível, pulando.", "WARN")

        # ── Auth / Brute Force ────────────────────────────────────────────────
        if self._should_run(["rate limit", "auth", "login", "credential", "bypass"]):
            print_status("[4/4] Auth Attacker", "INFO")
            attacker = AuthAttacker(self.target, self.findings, self.context)
            self.results["auth"] = attacker.run()
        else:
            print_status("[4/4] Auth — nenhum finding elegível, pulando.", "WARN")

        # ── Ataques Específicos/Avançados (Juice Shop / Lógica de Negócio) ────
        print_status("[+] Advanced/Business Logic Attacker", "INFO")
        juice_attacker = JuiceAttacker(self.target, self.findings, self.context)
        self.results["juice"] = juice_attacker.run()

        # Consolidação
        self._build_summary()
        self._build_insights()

        print_status("[PIPELINE 4] Attack Engine concluído.", "SUCCESS")
        for ins in self.results["insights"]:
            print_status(ins, "WARN")

        return self.results


def run_attack(target: str, full_results: dict, context=None) -> dict:
    """Entrypoint do Pipeline 4."""
    engine = AttackEngine(target, full_results, context)
    return engine.run()
