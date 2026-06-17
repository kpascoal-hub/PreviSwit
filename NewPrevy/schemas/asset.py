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
