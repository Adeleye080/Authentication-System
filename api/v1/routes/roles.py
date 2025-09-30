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
    SecondaryRoleAssignmentRequest,
    PrimaryRoleUpdate,
)
from api.v1.services import (
    user_service,
    audit_log_service,
    notification_service,
    secondary_role_service,
)
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
    - user → superadmin
    """

    if not is_uuid(user_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User ID must be a valid UUID",
        )

    updated_user = user_service.upgrade_user_primary_role(
        db=db, user_id=user_id, new_role=data.new_role, assigner_id=admin.id
    )

    # Notify user of their role upgrade via email
    notification_service.send_role_upgrade_email(
        user_email=updated_user.email,
        new_role=data.new_role,
        bgt=bgt,
    )

    # Log the action to audit logs
    # audit_log_service.log(db=db, background_task=bgt, schema=AuditLogCreate())

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
    user_id: str,
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
    - superadmin → user
    """

    # Perform the role downgrade
    updated_user = user_service.downgrade_user_primary_role(
        db, user_id, data.new_role, admin.id
    )
    # if applicable, notify user of their role downgrade via email
    # Log the action

    return JsonResponseDict(
        message=f"User role downgraded to {data.new_role}",
        data={"user_id": user_id, "new_role": data.new_role},
    )


@roles_router.post(
    "/secondary/new",
    status_code=status.HTTP_201_CREATED,
    summary="Create new secondary role",
)
async def create_secondary_role(
    data: SecondaryRoleCreate,
    bgt: BackgroundTasks,
    db: Session = Depends(get_db),
    superadmin: User = Depends(user_service.get_current_superadmin),
):
    """Create a new secondary role with custom permissions"""

    secondary_role = await secondary_role_service.create_secondary_role(
        db=db, data=data, creator_id=superadmin.id
    )

    # log the action to audit logs

    return JsonResponseDict(
        message="Secondary role created successfully",
        data=secondary_role,
    )


@roles_router.delete(
    "/secondary/{role_id}",
    status_code=status.HTTP_200_OK,
    summary="Delete a secondary role",
)
async def delete_secondary_role(
    role_id: int,
    db: Session = Depends(get_db),
    superadmin: User = Depends(user_service.get_current_superadmin),
):
    """Delete a secondary role"""

    deleted_role_name, _ = await secondary_role_service.delete_role(
        db=db, role_id=role_id, action_by=superadmin
    )

    return JsonResponseDict(message=f"Successfully deleted '{deleted_role_name}' role")


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

    updated_role = await secondary_role_service.update_secondary_role(
        db=db, role_id=role_id, data=data, updater_id=user.id
    )

    # Log the action to audit logs

    return JsonResponseDict(
        message="Secondary role updated successfully",
        data=updated_role,
    )


@roles_router.post(
    "/secondary/assign/{user_id}",
    status_code=status.HTTP_200_OK,
    summary="Assign secondary role to user",
)
async def assign_secondary_role(
    user_id: str,
    data: SecondaryRoleAssignmentRequest,
    bgt: BackgroundTasks,
    db: Session = Depends(get_db),
    admin: User = Depends(user_service.get_current_user),
):
    """Assign secondary role(s) to a user"""

    user_service.ensure_administrator(admin)
    if not is_uuid(user_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User ID must be a valid UUID",
        )

    await secondary_role_service.assign_role_to_user(
        db=db, user_id=user_id, role_ids=data.role_ids, assigner=admin
    )

    return JsonResponseDict(
        message="Role(s) assigned successfully",
        data={"user_id": user_id, "assigned_role_ids": data.role_ids},
    )


@roles_router.delete(
    "/revoke/{user_id}/{role_id}",
    status_code=status.HTTP_200_OK,
    summary="Revoke secondary role from user",
)
async def revoke_secondary_role(
    user_id: str,
    role_id: int,
    bgt: BackgroundTasks,
    db: Session = Depends(get_db),
    admin: User = Depends(user_service.get_current_user),
):
    """Revoke a secondary role from a user"""

    user_service.ensure_administrator(admin)

    if not is_uuid(user_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User ID must be a valid UUID",
        )

    await secondary_role_service.revoke_role_from_user(
        db=db, user_id=user_id, role_id=role_id, revoker=admin
    )

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
    summary="List all available secondary roles",
)
async def list_secondary_roles(
    db: Session = Depends(get_db),
    admin: User = Depends(user_service.get_current_user),
):
    """List all available secondary roles"""

    user_service.ensure_administrator(admin)

    available_roles = await secondary_role_service.get_all_roles(db)

    return JsonResponseDict(
        message="Successfully fetched all available roles",
        data=available_roles,
    )


@roles_router.get(
    "/user/{user_id}",
    # response_model=List[SecondaryRoleResponse],
    status_code=status.HTTP_200_OK,
    summary="Get user's secondary roles",
)
async def get_user_secondary_roles(
    user_id: str,
    db: Session = Depends(get_db),
    admin: User = Depends(user_service.get_current_user),
):
    """Get all secondary roles assigned to a user"""

    user_service.ensure_administrator(admin)
    if not is_uuid(user_id):
        raise HTTPException(detail="user id must be valid UUID")

    user, user_roles = await secondary_role_service.fetch_roles_assigned_to_user(
        db=db, user_id=user_id, request_user=admin
    )

    response = {
        "user_id": user.id,
        "roles": [role.to_dict(hide_creator=True) for role in user_roles],
    }

    return JsonResponseDict(message="successfully fetch user role(s)", data=response)
