from fastapi import APIRouter, status, Depends, HTTPException, Request, BackgroundTasks
from uuid import UUID
from sqlalchemy.orm import Session
from db.database import get_db

from api.utils.json_response import JsonResponseDict
from api.v1.models.user import User
from api.v1.models.audit_logs import AuditLog
from api.v1.schemas.user import (
    UserCreate,
    UserResponseModel,
    UserUpdateSchema,
    UserUpdateResponseModel,
    AllUsersResponse,
)
from api.v1.schemas.audit_logs import (
    AuditLogCreate,
    AuditLogEventEnum,
    AuditLogStatuses,
)
from api.utils.responses import all_users_response
from api.v1.services import (
    user_service,
    geoip_service,
    devices_service,
    audit_log_service,
    notification_service,
)
from api.utils.validators import check_model_existence
from api.utils.settings import settings
from api.utils.user_device_agent import get_device_info
from smtp.mailing import send_mail
import logging


user_router = APIRouter(prefix="/users")
logger = logging.getLogger(__name__)


@user_router.post(
    "/register",
    response_model=UserResponseModel,
    status_code=status.HTTP_201_CREATED,
    tags=["User"],
)
async def create_new_auth_user(
    request: Request,
    data: UserCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    _: None = Depends(geoip_service.blacklisted_country_dependency_check),
):
    """
    Registers new user in the auth system
    """

    try:
        new_user = user_service.create(db=db, schema=data)
    except HTTPException as exc:
        return JsonResponseDict(
            status_code=exc.status_code,
            status="failed",
            message=exc.detail,
        )

    # save user device info
    device_info = await get_device_info(request)
    if device_info:
        user_device = devices_service.create(
            db=db, owner=new_user, device_info=device_info
        )

    # send verification mail to user
    notification_service.send_verify_email_mail(user=new_user, bgt=background_tasks)

    # log activities both for audit and normal logging
    logger.info(f"Created new user: <{new_user.email}>")

    # Audit Log event
    try:
        schema = AuditLogCreate(
            user_id=new_user.id,
            event=AuditLogEventEnum.CREATE_ACCOUNT,
            description="Created new auth user account",
            ip_address=device_info.get("ip_address", "Not Captured"),
            status=AuditLogStatuses.SUCCESS,
            user_agent=device_info.get("user_agent", "Not Captured"),
        )
        audit_log_service.log(db=db, schema=schema, background_task=background_tasks)

        # log to logger
        logger.info(f"Audit Log ({new_user.email}) account creation")

    except Exception as exc:
        logger.error(
            f"Failed to Audit Log ({new_user.email}) creation, but seems account creation was successful: Error - {exc}"
        )

    return JsonResponseDict(
        status_code=201, message="created Auth user", data=new_user.to_dict()
    )


@user_router.get(
    "/getusers",
    response_model=AllUsersResponse,
    status_code=status.HTTP_200_OK,
    summary="Fetches auth users using filters",
    tags=["Moderator", "Superadmin"],
)
async def get_auth_users(
    page: int = 1,
    per_page: int = 50,
    active: bool = True,
    verified: bool = True,
    deleted: bool = False,
    db: Session = Depends(get_db),
    user: User = Depends(user_service.get_current_user),
):
    """
    Retrieves Auth users from the system.\n
    Use the `deleted`, `active` and `verified` filters to get the desired result.\n
    **NOTE:**
    - **Maximum** item per page is **50** and **Minimum** item per page is **1**, If set outside the scope, the default values would be used.
    """

    page = max(page, 1)
    per_page = max(per_page, 1)
    if per_page > 50:
        per_page = 50

    users, total_users = user_service.fetch_all_paginated_with_filters(
        db=db,
        page=page,
        per_page=per_page,
        is_active=active,
        is_deleted=deleted,
        is_verified=verified,
    )
    user_count = len(users)
    total_pages = (total_users + per_page - 1) // per_page

    return all_users_response(
        message="retrieved all users",
        current_page=page,
        per_page=per_page,
        total=total_users,
        total_pages=total_pages,
        count=user_count,
        status_code=200,
        data=[user.to_dict() for user in users],
        prev_page=f"/?page={page - 1}" if page > 1 else None,
        next_page=f"/?page={page + 1}" if page < total_pages else None,
    )


@user_router.get(
    "/@me",
    response_model=UserResponseModel,
    status_code=status.HTTP_200_OK,
    tags=["User"],
)
async def get_an_auth_user(
    user: User = Depends(user_service.get_current_user),
):
    """
    Retrieve an Auth user.
    """

    return JsonResponseDict(
        message="Retrieve user successfully",
        data=user.to_dict(),
        status_code=status.HTTP_200_OK,
    )


@user_router.patch(
    "/@me",
    response_model=UserUpdateResponseModel,
    status_code=status.HTTP_200_OK,
    tags=["User"],
)
async def patch_auth_user(
    data: UserUpdateSchema,
    user: User = Depends(user_service.get_current_user),
    db: Session = Depends(get_db),
):
    """Update Auth user data"""

    try:
        updated_user = user_service.update(db=db, user_obj=user, schema=data)
    except HTTPException as exc:
        return JsonResponseDict(
            message="failed to update user",
            error=exc.detail,
            status_code=exc.status_code,
        )

    return JsonResponseDict(
        message="user updated successfully",
        data=updated_user.to_dict(),
        status_code=200,
    )


@user_router.delete(
    "/@me",
    response_model=UserResponseModel,
    status_code=status.HTTP_200_OK,
    summary="Deletes a user",
    tags=["User"],
)
async def soft_delete_auth_user(
    user: User = Depends(user_service.get_current_user),
    db: Session = Depends(get_db),
):
    """
    CAUTION!!

    Self delete user from the system
    """

    try:
        user = user_service.delete(db=db, user_id=user.id)
    except HTTPException as exc:
        return JsonResponseDict(
            message="Failed to delete user from the system",
            error=f"{exc.detail}",
            status_code=exc.status_code,
        )

    return user.to_dict()


@user_router.delete(
    "/delete/{user_id}",
    response_model=UserResponseModel,
    status_code=status.HTTP_200_OK,
    summary="Deletes a user in the system",
    tags=["Superadmin", "Moderator"],
)
def soft_delete_auth_user(
    user_id: UUID,
    db: Session = Depends(get_db),
    user: User = Depends(user_service.get_current_user),
):
    """
    Caution!!

    This endpoint removes a user from the system totally
    Only accessible to superadmins
    """

    if not any([user.is_superadmin, user.is_moderator]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You cannot perform this action",
        )

    try:
        user = user_service.delete(db=db, user_id=user_id)
    except HTTPException as exc:
        return JsonResponseDict(
            message=exc.detail,
            status="failed",
            status_code=exc.status_code,
        )

    return user.to_dict()


@user_router.delete(
    "/hard-delete",
    response_model=UserResponseModel,
    status_code=status.HTTP_200_OK,
    summary="Removes a user entirely from the system",
    tags=["Superadmin"],
)
async def hard_delete_auth_user(
    user_id: UUID,
    bgt: BackgroundTasks,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(user_service.get_current_user),
):
    """
    Caution!!

    This endpoint removes a user from the system totally
    Only accessible to superadmins
    """

    if not user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not enough permission",
        )

    if user_id == user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot delete yourself",
        )

    try:
        deleted_user = user_service.hard_delete_user(db=db, user_id=user_id)
    except HTTPException as exc:
        return JsonResponseDict(
            message=exc.detail,
            status="failed",
            status_code=exc.status_code,
        )

    superadmin_device_info = await get_device_info(request)

    deleted_user_details = deleted_user.to_dict(hide_sensitive_data=False)

    audit_log_service.log(
        db=db,
        background_task=bgt,
        schema=AuditLogCreate(
            user_id=user.id,
            event=AuditLogEventEnum.HARD_DELETE,
            description=f"superadmin ({user.id} - {user.email}) hard deleted a user. view deleted user info in details",
            details=deleted_user_details,
            status=AuditLogStatuses.SUCCESS,
            ip_address=superadmin_device_info.get("ip_address", "Not Captured"),
            user_agent=superadmin_device_info.get("user_agent", "Not Captured"),
        ),
    )

    # send mail to deleted user if applicable

    return deleted_user_details
