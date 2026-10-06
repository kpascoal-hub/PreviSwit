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
