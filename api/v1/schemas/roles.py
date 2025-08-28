"""Role schemas module."""

from typing import List, Optional
from pydantic import BaseModel, Field, validator
from datetime import datetime


class Permission(BaseModel):
    """Permission schema"""

    resource: str = Field(..., description="The resource this permission applies to")
    actions: List[str] = Field(
        ..., description="List of allowed actions (e.g., read, write, delete)"
    )


class SecondaryRoleBase(BaseModel):
    """Base secondary role schema"""

    name: str = Field(..., min_length=2, max_length=50)
    description: str = Field(..., min_length=10, max_length=200)
    permissions: List[Permission] = Field(
        ..., description="List of permissions for this role"
    )
    organization_id: Optional[int] = Field(
        None, description="Organization this role belongs to"
    )

    @validator("permissions")
    def validate_permissions(cls, v):
        """Validate permissions format"""
        valid_actions = {"read", "write", "delete", "manage", "execute"}
        for perm in v:
            invalid_actions = set(perm.actions) - valid_actions
            if invalid_actions:
                raise ValueError(f"Invalid actions found: {invalid_actions}")
        return v


class SecondaryRoleCreate(SecondaryRoleBase):
    """Schema for creating a secondary role"""

    pass


class SecondaryRoleUpdate(BaseModel):
    """Schema for updating a secondary role"""

    name: Optional[str] = Field(None, min_length=2, max_length=50)
    description: Optional[str] = Field(None, min_length=10, max_length=200)
    permissions: Optional[List[Permission]] = Field(None)
    is_active: Optional[bool] = Field(None)

    @validator("permissions")
    def validate_permissions(cls, v):
        if v is not None:
            valid_actions = {"read", "write", "delete", "manage", "execute"}
            for perm in v:
                invalid_actions = set(perm.actions) - valid_actions
                if invalid_actions:
                    raise ValueError(f"Invalid actions found: {invalid_actions}")
        return v


class SecondaryRoleResponse(SecondaryRoleBase):
    """Response schema for secondary role"""

    id: int
    is_active: bool
    created_at: datetime
    updated_at: Optional[datetime]
    created_by: int

    class Config:
        """Pydantic config"""

        from_attributes = True


class RoleAssignmentRequest(BaseModel):
    """Schema for assigning roles to a user"""

    role_ids: List[int] = Field(..., description="List of secondary role IDs to assign")
    expires_at: Optional[datetime] = Field(
        None, description="Optional expiration date for the role assignment"
    )
