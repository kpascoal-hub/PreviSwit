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
import sys
from colorama import Fore, Style, init
init()

# Força UTF-8 no terminal do Windows para suportar emojis e caracteres especiais
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

def show_banner():
    try:
        print(f"""{Fore.CYAN}
        
{Fore.RED}
        [*] PREVISWIT  v3.0  --  AI-Powered Pentest Framework
{Fore.WHITE}        Pipeline: Tradicional  |  Agressivo  |  IA
        Autor  : PreviSwit  |  Uso exclusivo em alvos autorizados
{Style.RESET_ALL}""")
    except UnicodeEncodeError:
        print("=== PREVISWIT v3.0 — AI-Powered Pentest Framework ===")
