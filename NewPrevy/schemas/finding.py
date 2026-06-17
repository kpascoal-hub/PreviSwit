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
