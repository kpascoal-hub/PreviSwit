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
import os, importlib
from modules.plugins.base_plugin import BasePlugin

def load_plugins() -> list[BasePlugin]:
    plugins  = []
    skip     = {"loader.py","base_plugin.py","__init__.py"}
    pkg_path = os.path.join(os.path.dirname(__file__))

    for fname in os.listdir(pkg_path):
        if not fname.endswith(".py") or fname in skip:
            continue
        mod_name = f"modules.plugins.{fname[:-3]}"
        try:
            mod = importlib.import_module(mod_name)
            for attr in dir(mod):
                obj = getattr(mod, attr)
                try:
                    if issubclass(obj, BasePlugin) and obj is not BasePlugin:
                        plugins.append(obj())
                except TypeError:
                    pass
        except Exception:
            pass
    return plugins
