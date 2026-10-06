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
"""PreviSwit — Schemas: Risk"""
from pydantic import BaseModel
from typing import Optional, Dict
from enum import Enum


class RiskLevelEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskScore(BaseModel):
    score: float
    level: RiskLevelEnum
    open_findings: int
    timestamp: str
    description: Optional[str] = None


class ComplianceStatus(BaseModel):
    framework: str
    compliance_percentage: float
    status: str  # compliant, partial, non_compliant
    open_findings_mapped: Optional[int] = None
