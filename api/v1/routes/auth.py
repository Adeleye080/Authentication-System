"""
Authentication Module
Handles user login, logout and refresh token routes
"""

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from api.v1.schemas.user import UserLogin, LoginResponseModel
from api.v1.services import user_service
from api.utils.json_response import JsonResponseDict
from api.utils.responses import auth_response
from db.database import get_db


auth_router = APIRouter(tags=["Auth"])


@auth_router.post("/login", response_model=LoginResponseModel)
async def login(data: UserLogin, db: Session = Depends(get_db)):
    """Logs client in

    **Cient may be regular users, moderator of admin

    **Payload:**

        - `email`
        - `password`
    """

    try:
        user = user_service.authenticate_user(
            db=db, email=data.email, password=data.password
        )
        # convert user object to dictionary
        user.to_dict()
    except HTTPException as exc:
        return JsonResponseDict(
            message="Login Operation failed",
            error=exc.detail,
            status_code=exc.status_code,
        )

    # generate user tokens
    user_access_token = user_service.create_access_token(user_id=user.id)
    user_refresh_token = user_service.create_refresh_token(db=db, user_id=user.id)

    return auth_response(
        status="success",
        status_code=200,
        message="Login was successful",
        user_data=user,
        refresh_token=user_refresh_token,
        access_token=user_access_token,
    )
