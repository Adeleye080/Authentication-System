"""Role schemas module."""

from typing import List, Optional
from pydantic import BaseModel, Field, model_validator
from datetime import datetime
from enum import Enum


class Permission(BaseModel):
    """Permission schema"""

    resource: str = Field(..., description="The resource this permission applies to")
    actions: List[str] = Field(
        ..., description="List of allowed actions (e.g., read, write, delete)"
    )

    @model_validator(mode="before")
    @classmethod
    def validate_permissions(cls, v):
        """Validate permissions format"""
        valid_actions = {"read", "write", "delete", "manage", "execute"}
        for perm in v:
            invalid_actions = set(perm.actions) - valid_actions
            if invalid_actions:
                raise ValueError(f"Invalid actions found: {invalid_actions}")
        return v


class SecondaryRoleCreate(BaseModel):
    """Schema for creating a secondary role"""

    name: str = Field(..., min_length=2, max_length=50)
    description: str = Field(..., min_length=10, max_length=258)


class SecondaryRoleUpdate(BaseModel):
    """Schema for updating a secondary role"""

    name: Optional[str] = Field(
        None, min_length=2, max_length=50, examples=["editor", "producer"]
    )
    description: Optional[str] = Field(
        None,
        min_length=10,
        max_length=200,
        examples=["Can edit content", "Can manage users"],
    )
    reason: str = Field(
        ...,
        min_length=10,
        max_length=258,
        examples=[
            "Updating role to reflect new responsibilities",
            "Correcting role description",
        ],
    )

    @model_validator(mode="before")
    @classmethod
    def validate_update(cls, values: dict):
        """Ensure at least one field is being updated"""
        if not any(values.get(field) for field in ["name", "description"]):
            raise ValueError("At least one of 'name' or 'description' must be provided")
        return values


class SecondaryRoleResponse(BaseModel):
    """Response schema for secondary role"""

    id: str
    name: str
    description: str
    # is_active: bool
    created_at: datetime
    created_by: str

    class Config:
        """Pydantic config"""

        from_attributes = True


class SecondaryRoleAssignmentRequest(BaseModel):
    """Schema for assigning roles to a user"""

    role_ids: List[int] = Field(..., description="List of secondary role IDs to assign")


class PrimaryRoleEnum(str, Enum):
    """Enum for primary roles"""

    USER = "user"
    MODERATOR = "moderator"
    SUPERADMIN = "superadmin"


class PrimaryRoleUpdate(BaseModel):
    """Schema for updating a user's primary role"""

    new_role: str = Field(
        ...,
        description="The new role to assign to the user",
        examples=["moderator", "superadmin"],
    )

    @model_validator(mode="before")
    @classmethod
    def validate_role_change(cls, values: dict):
        """Validate that the role change is allowed"""
        if "new_role" in values:
            v = values.get("new_role")
            if v not in PrimaryRoleEnum.__members__.values():
                raise ValueError(f"Invalid role: {v}")

        return values
