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
