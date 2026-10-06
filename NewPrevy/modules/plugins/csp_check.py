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
from modules.plugins.base_plugin import BasePlugin

WEAK_DIRECTIVES = ["unsafe-inline","unsafe-eval","*"]

class CSPCheck(BasePlugin):
    name     = "csp_check"
    severity = "MEDIUM"

    def run(self, url, response):
        csp = response.headers.get("Content-Security-Policy","")
        if not csp:
            return {"url": url, "issue": "CSP ausente", "severity": "MEDIUM", "source": "Plugin:CSPCheck"}
        weak = [d for d in WEAK_DIRECTIVES if d in csp]
        if weak:
            return {
                "url": url,
                "issue": f"CSP fraca — diretivas perigosas: {weak}",
                "severity": "MEDIUM",
                "source": "Plugin:CSPCheck"
            }
