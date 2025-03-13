from fastapi import APIRouter, status, Depends
from uuid import UUID
from sqlalchemy.orm import Session
from db.database import get_db

from api.utils.json_response import JsonResponseDict
from api.utils.responses import all_users_response
from api.v1.models.user import User
from api.v1.schemas.user import (
    UserCreate,
    UserResponseModel,
    UserUpdateSchema,
    AllUsersResponse,
    UserUpdateResponseModel,
)
from api.v1.services import user_service
from api.utils.validators import check_model_existence


user_router = APIRouter(prefix="/auth", tags=["Authentication"])


# PLEASE NOTE THAT ALL USER ID ARE TO BE GOTTEN FROM THE JWT TOKEN
# AND NOT FROM THE URL PARAMS
# THIS IS TO ENSURE THAT USERS CAN ONLY ACCESS THEIR OWN DATA
# AND NOT OTHER USERS' DATA


@user_router.post(
    "/register", response_model=UserResponseModel, status_code=status.HTTP_201_CREATED
)
async def create_new_auth_user(request: UserCreate, db: Session = Depends(get_db)):
    """
    Registers new user in the auth system
    """

    new_user = user_service.create(db=db, schema=request)

    return JsonResponseDict(
        status_code=201, message="created user authentication", data=new_user.to_dict()
    )


@user_router.get(
    "/allusers", response_model=AllUsersResponse, status_code=status.HTTP_200_OK
)
async def get_all_auth_users(
    page: int = 1, per_page: int = 10, db: Session = Depends(get_db)
):
    """
    Retrieve all Auth users, typically to superadmin
    """

    if page < 1:
        page = 1
    if per_page < 1:
        per_page = 10

    # in the future add paginated database query
    users, total_users = user_service.fetch_all_paginated(
        db=db, page=page, per_page=per_page
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
    "/{user_id}", response_model=UserResponseModel, status_code=status.HTTP_200_OK
)
async def get_auth_user(user_id: UUID, db: Session = Depends(get_db)):
    """
    Retrieve an Auth user, typically to superadmin
    """

    user_id = str(user_id)
    try:
        user = check_model_existence(db=db, model=User, id=user_id)
    except Exception as exc:
        return JsonResponseDict(
            message="failed to get user from the system",
            error=exc.detail,
            status_code=exc.status_code,
        )

    return user.to_dict()


@user_router.patch(
    "/{user_id}", response_model=UserUpdateResponseModel, status_code=status.HTTP_200_OK
)
async def patch_auth_user(
    user_id: UUID,
    data: UserUpdateSchema,
    db: Session = Depends(get_db),
):
    """Update Auth user data"""

    user_id = str(user_id)

    try:
        user = check_model_existence(db=db, model=User, id=user_id)
    except Exception as exc:
        return JsonResponseDict(
            message="failed to get user from the system",
            error=exc.detail,
            status_code=exc.status_code,
        )

    try:
        updated_user = user_service.update(db=db, user_id=user_id, schema=data)
    except Exception as exc:
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
    "/{user_id}/me", response_model=UserResponseModel, status_code=status.HTTP_200_OK
)
def soft_delete_auth_user(user_id: UUID, db: Session = Depends(get_db)):
    """
    Caution!!
    This endpoint deletes a user from the system
    Accessible to users and moderators
    """
    pass


@user_router.delete(
    "/{user_id}", response_model=UserResponseModel, status_code=status.HTTP_200_OK
)
def hard_delete_auth_user(user_id: UUID, db: Session = Depends(get_db)):
    """
    Caution!!
    This endpoint removes a user from the system totally
    Only accessible to superadmins
    """
    pass
