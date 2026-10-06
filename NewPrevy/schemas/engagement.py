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
"""PreviSwit — Schemas: Engagement"""
from pydantic import BaseModel
from typing import List, Optional, Dict
from datetime import datetime


class EngagementCreate(BaseModel):
    asset_id: Optional[str] = None
    target: str
    pipeline: str = "all"
    status: str = "pending"
    scan_tools_used: Optional[List[str]] = []


class EngagementRead(BaseModel):
    id: str
    asset_id: Optional[str] = None
    target: str
    pipeline: str
    status: str
    findings_count: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    duration_seconds: int = 0
    scan_tools_used: List[str] = []
    report_path: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    created_at: str

    class Config:
        from_attributes = True


class ScanResult(BaseModel):
    """Resultado de um scan para persistência."""
    engagement_id: str
    findings: List[dict] = []
    raw_outputs: Dict[str, str] = {}
    duration_seconds: int = 0
    tools_used: List[str] = []
