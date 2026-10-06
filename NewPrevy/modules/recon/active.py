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
import nmap, subprocess
from urllib.parse import urlparse
from core.utils import print_status, safe_request
from config import Config

SECURITY_HEADERS = [
    "Strict-Transport-Security","X-Frame-Options","X-Content-Type-Options",
    "Content-Security-Policy","Referrer-Policy","Permissions-Policy"
]

class ActiveRecon:
    def __init__(self, target):
        self.target  = target
        parsed = urlparse(target)
        self.domain  = parsed.hostname or parsed.netloc or target
        self.results = {"nmap":{},"gobuster":[],"headers":{},"missing_headers":[],"cookies":[]}

    def run_nmap(self):
        print_status(f"Nmap em {self.domain}...", "INFO")
        try:
            nm = nmap.PortScanner()
            nm.scan(self.domain, arguments="-sV -T4 --top-ports 100 --script=banner")
            for host in nm.all_hosts():
                host_data = {}
                for proto in nm[host].all_protocols():
                    host_data[proto] = {
                        port: nm[host][proto][port]
                        for port in nm[host][proto]
                    }
                self.results["nmap"][host] = host_data
            print_status(f"Nmap: {len(self.results['nmap'])} hosts", "SUCCESS")
        except Exception as e:
            print_status(f"Nmap: {e}", "ERROR")

    def run_gobuster(self):
        print_status("Gobuster dir brute...", "INFO")
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        try:
            cmd = [Config.GOBUSTER_PATH,"dir","-u",self.target,"-w",wordlist,
                   "-q","--no-color","-t","20","-s","200,204,301,302,403"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            for line in proc.stdout.split("\n"):
                line = line.strip()
                if line:
                    self.results["gobuster"].append(line)
            print_status(f"Gobuster: {len(self.results['gobuster'])} paths", "SUCCESS")
        except FileNotFoundError:
            print_status("Gobuster não instalado.", "ERROR")
        except Exception:
            pass

    def check_headers(self):
        print_status("Análise de headers HTTP...", "INFO")
        r = safe_request(self.target)
        if not r:
            return
        self.results["headers"] = dict(r.headers)
        missing = [h for h in SECURITY_HEADERS if h not in r.headers]
        self.results["missing_headers"] = missing
        # Análise de cookies
        for cookie in r.cookies:
            flags = []
            if not cookie.has_nonstandard_attr("HttpOnly"):
                flags.append("sem HttpOnly")
            if not cookie.secure:
                flags.append("sem Secure")
            if flags:
                self.results["cookies"].append({"name": cookie.name, "issues": flags})
        if missing:
            print_status(f"Headers ausentes: {missing}", "WARN")

    def execute_all(self):
        self.run_nmap()
        self.run_gobuster()
        self.check_headers()
        return self.results
