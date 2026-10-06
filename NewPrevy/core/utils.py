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
import requests
import warnings
from colorama import Fore, Style
from config import Config

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

def safe_request(url, method="GET", data=None, headers=None, timeout=None):
    try:
        h = {"User-Agent": Config.USER_AGENT}
        if headers:
            h.update(headers)
        return requests.request(
            method, url, headers=h, data=data,
            timeout=timeout or Config.TIMEOUT, verify=False
        )
    except Exception:
        return None

def print_status(msg, level="INFO"):
    clr = {"INFO": Fore.CYAN, "SUCCESS": Fore.GREEN, "WARN": Fore.YELLOW,
           "ERROR": Fore.RED, "CRIT": Fore.MAGENTA}
    sym = {"INFO": "[*]", "SUCCESS": "[+]", "WARN": "[!]", "ERROR": "[-]", "CRIT": "[!!]"}
    print(f"{clr.get(level, Fore.WHITE)}{sym.get(level,'[*]')} {msg}{Style.RESET_ALL}")
