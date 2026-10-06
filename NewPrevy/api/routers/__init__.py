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
PreviSwit AI-ASPM — Routers Package
Expõe todos os domínios ASPM como routers FastAPI.
"""
from api.routers.auth         import router as auth_router
from api.routers.assets       import router as assets_router
from api.routers.engagements  import router as engagements_router
from api.routers.findings     import router as findings_router
from api.routers.ai_insights  import router as ai_router
from api.routers.risk         import router as risk_router
from api.routers.reports      import router as reports_router
from api.routers.integrations import router as integrations_router
from api.routers.settings      import router as settings_router
from api.routers.aspm_parsers  import router as aspm_parsers_router
from api.routers.cloud         import router as cloud_router

__all__ = [
    "auth_router",
    "assets_router",
    "engagements_router",
    "findings_router",
    "ai_router",
    "risk_router",
    "reports_router",
    "integrations_router",
    "settings_router",
    "aspm_parsers_router",
    "cloud_router",
]

