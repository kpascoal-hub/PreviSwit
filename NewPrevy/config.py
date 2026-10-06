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
import os

class Config:
    USER_AGENT    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    TIMEOUT       = 10
    MAX_PAGES     = 40
    REPORT_DIR    = "reports"
    DATA_DIR      = "data"
    DB_PATH       = "data/results.db"
    AI_MEMORY     = "data/ai_memory.json"
    NIKTO_PATH    = "nikto"
    GOBUSTER_PATH = "gobuster"

    @staticmethod
    def ensure_dirs():
        for d in [Config.REPORT_DIR, Config.DATA_DIR]:
            os.makedirs(d, exist_ok=True)
