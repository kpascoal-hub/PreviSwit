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
PreviSwit AI-ASPM — Schemas Package
Modelos Pydantic centralizados para validação e serialização.
"""
from schemas.asset      import AssetCreate, AssetRead, AssetUpdate
from schemas.engagement import EngagementCreate, EngagementRead
from schemas.finding    import FindingCreate, FindingRead, FindingStatusUpdate
from schemas.risk       import RiskScore
from schemas.user       import UserCreate, UserRead

__all__ = [
    "AssetCreate", "AssetRead", "AssetUpdate",
    "EngagementCreate", "EngagementRead",
    "FindingCreate", "FindingRead", "FindingStatusUpdate",
    "RiskScore",
    "UserCreate", "UserRead",
]
