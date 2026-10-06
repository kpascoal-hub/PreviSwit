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
"""PreviSwit — Schemas: Finding"""
from pydantic import BaseModel
from typing import Optional, List
from enum import Enum


class SeverityEnum(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatusEnum(str, Enum):
    OPEN = "open"
    IN_REMEDIATION = "in_remediation"
    VERIFIED = "verified"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class FindingCreate(BaseModel):
    title: str
    description: Optional[str] = ""
    severity: SeverityEnum = SeverityEnum.MEDIUM
    asset_id: Optional[str] = None
    engagement_id: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    url: Optional[str] = None
    endpoint: Optional[str] = None
    tool: Optional[str] = None
    raw_output: Optional[str] = None
    tags: Optional[List[str]] = []


class FindingStatusUpdate(BaseModel):
    status: FindingStatusEnum
    reason: Optional[str] = None


class FindingRead(FindingCreate):
    id: str
    status: FindingStatusEnum = FindingStatusEnum.OPEN
    ai_remediation: Optional[str] = None
    is_duplicate: bool = False
    duplicate_of: Optional[str] = None
    false_positive: bool = False
    false_positive_reason: Optional[str] = None
    created_at: str
    updated_at: str
    sla: Optional[dict] = None

    class Config:
        from_attributes = True
