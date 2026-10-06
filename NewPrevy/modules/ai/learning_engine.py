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
import json, os
from config import Config

class LearningEngine:
    def __init__(self):
        self.path   = Config.AI_MEMORY
        self.memory = self._load()

    def _load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path) as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def learn(self, issue: str):
        self.memory[issue] = self.memory.get(issue, 0) + 1
        self._save()

    def _save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w") as f:
            json.dump(self.memory, f, indent=2, ensure_ascii=False)

    def top_issues(self, n=10):
        return sorted(self.memory.items(), key=lambda x: x[1], reverse=True)[:n]

    def is_recurring(self, issue: str) -> bool:
        return self.memory.get(issue, 0) >= 2
