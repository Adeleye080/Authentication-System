from pydantic import BaseModel, EmailStr, StringConstraints, Field
from datetime import datetime
from typing import Annotated


class User(BaseModel):
    id: str
    email: EmailStr
    is_active: bool = True
    is_verified: bool = False
    is_deleted: bool = False
    created_at: datetime

    class Config:
        from_attributes = True


class UserCreate(BaseModel):
    """Schema to create a user"""

    email: EmailStr
    password: Annotated[
        str, StringConstraints(min_length=8, max_length=64, strip_whitespace=True)
    ]
    """Added the confirm_password field to UserCreate Model"""
    confirm_password: Annotated[
        str,
        StringConstraints(min_length=8, max_length=64, strip_whitespace=True),
        Field(exclude=True),  # exclude confirm_password field
    ]
