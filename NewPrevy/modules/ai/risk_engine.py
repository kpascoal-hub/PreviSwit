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
Risk Engine — pontua e prioriza findings com lógica multi-critério.
"""

SEV_SCORE = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}

KEYWORD_SCORE = {
    "rce": 9, "remote code": 9, "command injection": 9,
    "sqli": 8, "sql injection": 8, "sql": 6,
    "ssrf": 7, "path traversal": 7, "lfi": 7,
    "xss": 5, "csrf": 5, "idor": 6,
    "secret": 6, "token": 5, "key": 4, "password": 4,
    "admin": 4, "root": 4, "debug": 3,
    "cors": 4, "redirect": 3, "header": 2,
    "error": 2, "exposed": 3,
}


class RiskEngine:
    def score(self, finding: dict) -> float:
        total = 0.0
        sev   = finding.get("severity", "INFO").upper()
        total += SEV_SCORE.get(sev, 0)

        text = " ".join([
            finding.get("issue",""),
            finding.get("type",""),
            finding.get("url",""),
        ]).lower()

        for kw, pts in KEYWORD_SCORE.items():
            if kw in text:
                total += pts
                break  # evita double-counting de variantes

        # Bônus por evidência concreta
        if finding.get("evidence") or finding.get("payload"):
            total += 2

        return total

    def prioritize(self, findings: list) -> list:
        return sorted(findings, key=self.score, reverse=True)

    def classify(self, finding: dict) -> str:
        s = self.score(finding)
        if s >= 15: return "CRITICAL"
        if s >= 10: return "HIGH"
        if s >= 5:  return "MEDIUM"
        return "LOW"
