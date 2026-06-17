"""PreviSwit — Schemas: User"""
from pydantic import BaseModel, EmailStr
from typing import Optional
from enum import Enum


class RoleEnum(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    DEVELOPER = "developer"
    VIEWER = "viewer"


class UserCreate(BaseModel):
    username: str
    email: Optional[str] = ""
    full_name: Optional[str] = ""
    role: RoleEnum = RoleEnum.VIEWER
    password: str


class UserRead(BaseModel):
    id: str
    username: str
    email: Optional[str] = ""
    full_name: Optional[str] = ""
    role: RoleEnum
    is_active: bool = True
    created_at: str
    last_login: Optional[str] = None

    class Config:
        from_attributes = True
