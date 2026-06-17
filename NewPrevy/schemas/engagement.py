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
