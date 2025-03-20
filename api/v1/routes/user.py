from fastapi import APIRouter, status, Depends, HTTPException, Security
from uuid import UUID
from sqlalchemy.orm import Session
from db.database import get_db

from api.utils.json_response import JsonResponseDict
from api.v1.models.user import User
from api.v1.schemas.user import (
    UserCreate,
    UserResponseModel,
    UserUpdateSchema,
    UserUpdateResponseModel,
    AllUsersResponse,
)
from api.utils.responses import all_users_response
from api.v1.services import user_service
from api.utils.validators import check_model_existence


user_router = APIRouter(prefix="/users")


# PLEASE NOTE THAT ALL USER ID ARE TO BE GOTTEN FROM THE JWT TOKEN
# AND NOT FROM THE URL PARAMS
# THIS IS TO ENSURE THAT USERS CAN ONLY ACCESS THEIR OWN DATA
# AND NOT OTHER USERS' DATA


@user_router.post(
    "/register",
    response_model=UserResponseModel,
    status_code=status.HTTP_201_CREATED,
    tags=["User"],
)
async def create_new_auth_user(request: UserCreate, db: Session = Depends(get_db)):
    """
    Registers new user in the auth system
    """

    try:
        new_user = user_service.create(db=db, schema=request)
    except HTTPException as exc:
        return JsonResponseDict(
            status_code=exc.status_code,
            error="Failed to create user",
            message=exc.detail,
        )

    return JsonResponseDict(
        status_code=201, message="created Auth user", data=new_user.to_dict()
    )


@user_router.get(
    "/allusers",
    response_model=AllUsersResponse,
    status_code=status.HTTP_200_OK,
    summary="Fetch users regardless of their status",
    tags=["Moderator", "Admin"],
)
async def get_all_auth_users(
    page: int = 1,
    per_page: int = 10,
    db: Session = Depends(get_db),
    user: User = Depends(user_service.get_current_user),
):
    """
    Retrieves all Auth users, typically to admins or moderators.

    - **Maximum** item per page is **50** and **Minimum** item per page is **1**

    - **Note:** Both **active**, **deleted** and **verified** users would be returned
    """

    # perform operation to check is current user is admin

    page = max(page, 1)
    per_page = max(per_page, 1)
    if per_page > 50:
        per_page = 50

    # paginated database query
    users, total_users = user_service.fetch_all_paginated(
        db=db, page=page, per_page=per_page
    )
    user_count = len(users)
    total_pages = (total_users + per_page - 1) // per_page

    if user_count == 0:

        return JsonResponseDict(
            status_code=400,
            error="Out of range",
            message="No users found on this page.",
        )

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
    "/getusers",
    response_model=AllUsersResponse,
    status_code=status.HTTP_200_OK,
    summary="Fetches active and verified users",
    tags=["Moderator", "Admin"],
)
async def get_active_and_verified_auth_users(
    page: int = 1, per_page: int = 10, db: Session = Depends(get_db)
):
    """
    Retrieves only **active** and **verified** Auth users from the system.

    - **Maximum** item per page is **50** and **Minimum** item per page is **1**
    """

    page = max(page, 1)
    per_page = max(per_page, 1)
    if per_page > 50:
        per_page = 50

    # in the future add paginated database query
    users, total_users = user_service.fetch_all_paginated_with_filters(
        db=db,
        page=page,
        per_page=per_page,
        is_active=True,
        is_deleted=False,
        is_verified=True,
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
    "/me",
    response_model=UserResponseModel,
    status_code=status.HTTP_200_OK,
    tags=["User"],
)
async def get_an_auth_user(
    user: User = Depends(user_service.get_current_user),
):
    """
    Retrieve an Auth user, typically to superadmin.
    """

    return JsonResponseDict(
        message="Retrieve user successfully",
        data=user.to_dict(),
        status_code=status.HTTP_200_OK,
    )


@user_router.patch(
    "/me",
    response_model=UserUpdateResponseModel,
    status_code=status.HTTP_200_OK,
    tags=["User"],
)
async def patch_auth_user(
    data: UserUpdateSchema,
    user: User = Depends(user_service.get_current_user),
):
    """Update Auth user data"""

    user_id = str(user_id)

    try:
        user = check_model_existence(db=db, model=User, id=user_id)
    except HTTPException as exc:
        return JsonResponseDict(
            message="failed to get user from the system",
            error=exc.detail,
            status_code=exc.status_code,
        )

    try:
        updated_user = user_service.update(db=db, user_id=user.id, schema=data)
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
    "/me",
    response_model=UserResponseModel,
    status_code=status.HTTP_200_OK,
    summary="Deletes a user",
    tags=["User"],
)
async def soft_delete_auth_user(
    user: User = Depends(user_service.get_current_user),
):
    """
    CAUTION!!

    This endpoint deletes a user from the system
    """

    user_id = str(user_id)
    user = check_model_existence(db=db, model=User, id=user_id)

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
    "/{user_id}hardDelete",
    response_model=UserResponseModel,
    status_code=status.HTTP_200_OK,
    summary="Removes a user entirely from the system",
    tags=["Admin"],
)
def hard_delete_auth_user(user_id: UUID, db: Session = Depends(get_db)):
    """
    Caution!!

    This endpoint removes a user from the system totally
    Only accessible to superadmins
    """

    pass
