"""Secondary roles routes module."""

from fastapi import APIRouter, Depends, status, BackgroundTasks, HTTPException
from sqlalchemy.orm import Session
from typing import List
from api.v1.models.user import User
from api.v1.schemas.audit_logs import (
    AuditLogCreate,
    AuditLogEventEnum,
    AuditLogStatuses,
)
from api.v1.schemas.roles import (
    SecondaryRoleCreate,
    SecondaryRoleUpdate,
    SecondaryRoleResponse,
    RoleAssignmentRequest,
    PrimaryRoleUpdate,
)
from api.v1.services import user_service, audit_log_service
from db.database import get_db
from api.utils.json_response import JsonResponseDict
from api.utils.validators import is_uuid

roles_router = APIRouter(prefix="/roles", tags=["Roles"])


@roles_router.put(
    "/primary/upgrade/{user_id}",
    status_code=status.HTTP_200_OK,
    summary="Upgrade user's primary role",
)
async def upgrade_primary_role(
    user_id: str,
    data: PrimaryRoleUpdate,
    bgt: BackgroundTasks,
    db: Session = Depends(get_db),
    admin: User = Depends(user_service.get_current_superadmin),
):
    """
    Upgrade a user's primary role. Only superadmins can perform this action.
    Available upgrades:
    - user → moderator
    - moderator → superadmin
    """

    if not is_uuid(user_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User ID must be a valid UUID",
        )

    updated_user = user_service.upgrade_user_primary_role(
        db=db, user_id=user_id, new_role=data.new_role, upgrader=admin.id
    )

    # Log the action to audit logs
    audit_log_service.log(db=db, background_task=bgt, schema=AuditLogCreate())

    return JsonResponseDict(
        message=f"User role upgraded to {data.new_role}",
        data={"user_id": user_id, "new_role": data.new_role},
    )


@roles_router.put(
    "/primary/downgrade/{user_id}",
    status_code=status.HTTP_200_OK,
    summary="Downgrade user's primary role",
)
async def downgrade_primary_role(
    user_id: int,
    data: PrimaryRoleUpdate,
    bgt: BackgroundTasks,
    db: Session = Depends(get_db),
    admin: User = Depends(user_service.get_current_superadmin),
):
    """
    Downgrade a user's primary role. Only superadmins can perform this action.
    Available downgrades:
    - superadmin → moderator
    - moderator → user
    """
    target_user = user_service.get_user_by_id(db, user_id)
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    # Prevent self-demotion
    if admin.id == target_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot downgrade your own role",
        )

    # Prevent downgrading the last superadmin
    if target_user.role == "superadmin":
        superadmin_count = user_service.count_superadmins(db)
        if superadmin_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot downgrade the last superadmin",
            )

    # Perform the role downgrade
    updated_user = user_service.downgrade_user_role(db, target_user, data.new_role)

    # Log the action
    bgt.add_task(
        audit_log_service.log_action,
        db,
        admin.id,
        "primary_role_downgrade",
        f"Downgraded user {user_id} to role {data.new_role}",
    )

    return JsonResponseDict(
        message=f"User role downgraded to {data.new_role}",
        data={"user_id": user_id, "new_role": data.new_role},
    )


@roles_router.post(
    "/secondary",
    response_model=SecondaryRoleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create new secondary role",
)
async def create_secondary_role(
    data: SecondaryRoleCreate,
    bgt: BackgroundTasks,
    db: Session = Depends(get_db),
    user: User = Depends(user_service.get_current_superadmin),
):
    """Create a new secondary role with custom permissions"""

    pass


@roles_router.put(
    "/secondary/{role_id}",
    response_model=SecondaryRoleResponse,
    status_code=status.HTTP_200_OK,
    summary="Update secondary role",
)
async def update_secondary_role(
    role_id: int,
    data: SecondaryRoleUpdate,
    bgt: BackgroundTasks,
    db: Session = Depends(get_db),
    user: User = Depends(user_service.get_current_superadmin),
):
    """Update an existing secondary role"""
    pass


@roles_router.post(
    "/secondary/assign/{user_id}",
    status_code=status.HTTP_200_OK,
    summary="Assign secondary role to user",
)
async def assign_secondary_role(
    user_id: int,
    data: RoleAssignmentRequest,
    bgt: BackgroundTasks,
    db: Session = Depends(get_db),
    admin: User = Depends(user_service.get_current_user),
):
    """Assign secondary role(s) to a user"""

    user_service.ensure_administrator(admin)

    pass

    # return JsonResponseDict(
    #     message="Roles assigned successfully",
    #     data={
    #         "assignments": [
    #             {"role_id": a.role_id, "expires_at": a.expires_at} for a in assignments
    #         ]
    #     },
    # )


@roles_router.delete(
    "/revoke/{user_id}/{role_id}",
    status_code=status.HTTP_200_OK,
    summary="Revoke secondary role from user",
)
async def revoke_secondary_role(
    user_id: int,
    role_id: int,
    bgt: BackgroundTasks,
    db: Session = Depends(get_db),
    admin: User = Depends(user_service.get_current_user),
):
    """Revoke a secondary role from a user"""

    user_service.ensure_administrator(admin)

    # Log the action
    # bgt.add_task(
    #     audit_log_service.log_action,
    #     db,
    #     admin.id,
    #     "secondary_role_revoke",
    #     f"Revoked role {role_id} from user {user_id}",
    # )

    return JsonResponseDict(message="Role revoked successfully")


@roles_router.get(
    "/secondary",
    response_model=List[SecondaryRoleResponse],
    status_code=status.HTTP_200_OK,
    summary="List all secondary roles",
)
async def list_secondary_roles(
    db: Session = Depends(get_db),
    admin: User = Depends(user_service.get_current_user),
):
    """List all available secondary roles"""

    user_service.ensure_administrator(admin)

    pass


@roles_router.get(
    "/user/{user_id}",
    response_model=List[SecondaryRoleResponse],
    status_code=status.HTTP_200_OK,
    summary="Get user's secondary roles",
)
async def get_user_secondary_roles(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(user_service.get_current_user),
):
    """Get all secondary roles assigned to a user"""
    pass
