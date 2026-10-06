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
"""PreviSwit — Schemas: Asset"""
from pydantic import BaseModel, HttpUrl
from typing import List, Optional, Dict
from datetime import datetime


class AssetBase(BaseModel):
    name: str
    description: Optional[str] = ""
    url: Optional[str] = ""
    technology_stack: Optional[List[str]] = []


class AssetCreate(AssetBase):
    pass


class AssetUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    url: Optional[str] = None
    technology_stack: Optional[List[str]] = None
    status: Optional[str] = None


class AssetRead(AssetBase):
    id: str
    risk_score: float = 0.0
    status: str = "active"
    findings_count: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
