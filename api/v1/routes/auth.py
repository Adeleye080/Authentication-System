"""
Authentication Module
Handles user login, logout and refresh token routes
"""

from typing import Annotated
from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from api.v1.schemas.user import UserLogin, LoginResponseModel, SwaggerLoginToken
from api.v1.services import user_service
from api.utils.json_response import JsonResponseDict
from api.utils.responses import auth_response
from db.database import get_db


auth_router = APIRouter(tags=["Auth"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/swagger-login")


@auth_router.post(
    "/login", response_model=LoginResponseModel, status_code=status.HTTP_200_OK
)
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

        # check user status (active, deleted, ...)
        user_service.perform_user_check(user=user)

        # convert user object to dictionary
        user_profile = user.to_dict()
    except HTTPException as exc:
        return JsonResponseDict(
            message="Could not authenticate user",
            error=exc.detail,
            status_code=exc.status_code,
        )

    try:
        # generate user tokens
        user_access_token = user_service.create_access_token(user_id=user.id)
        user_refresh_token = user_service.create_refresh_token(db=db, user_id=user.id)
    except HTTPException as exc:
        return JsonResponseDict(
            message="Login Operation failed",
            error=exc.detail,
            status_code=exc.status_code,
        )

    # perform other logic such as setting cookies
    # loging the event in audit logs

    return auth_response(
        status="success",
        status_code=200,
        message="Login was successful",
        user_data=user_profile,
        refresh_token=user_refresh_token,
        access_token=user_access_token,
    )


@auth_router.post(
    "/swagger-login", status_code=status.HTTP_200_OK, include_in_schema=False
)
async def login_in_openapi_swagger(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db),
):
    """
    Provides authentication for swagger UI Documentation testing
    """
    user = user_service.authenticate_user(
        db=db, email=form_data.username, password=form_data.password
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user_service.perform_user_check(user=user):
        access_token = user_service.create_access_token(user_id=user.id)

    return SwaggerLoginToken(access_token=access_token, token_type="bearer")


@auth_router.post(
    "/magic-link-login",
    response_model=LoginResponseModel,
    status_code=status.HTTP_200_OK,
)
async def magic_link_login(data: UserLogin, db: Session = Depends(get_db)):
    """Logs client in using magic link"""

    try:
        user = user_service.authenticate_user(
            db=db, email=data.email, password=data.password
        )

        # perform logic to check if user is active
        # perform logic to check if user is banned

        # convert user object to dictionary
        user_profile = user.to_dict()
    except HTTPException as exc:
        return JsonResponseDict(
            message="Could not authenticate user",
            error=exc.detail,
            status_code=exc.status_code,
        )

    try:
        # generate user tokens
        user_access_token = user_service.create_access_token(user_id=user.id)
        user_refresh_token = user_service.create_refresh_token(db=db, user_id=user.id)
    except HTTPException as exc:
        return JsonResponseDict(
            message="Login Operation failed",
            error=exc.detail,
            status_code=exc.status_code,
        )

    # perform other logic such as setting cookies
    # loging the event in audit logs

    return auth_response(
        status="success",
        status_code=200,
        message="Login was successful",
        user_data=user_profile,
        refresh_token=user_refresh_token,
        access_token=user_access_token,
    )


@auth_router.post("/logout", status_code=status.HTTP_200_OK)
async def logout(refresh_token: str, db: Session = Depends(get_db)):
    """Logs user out of the system"""

    refresh_token = refresh_token.get("refresh_token", None)
    if refresh_token:
        try:
            user_service.revoke_refresh_token(db=db, token=refresh_token)
        except HTTPException as exc:
            return JsonResponseDict(
                message="Could not revoke token",
                error=exc.detail,
                status_code=exc.status_code,
            )

        # perform other logic such as clearing cookies
        # loging the event in audit logs

        response = {"message": "Logout successful", "status_code": 200}
        return JSONResponse(status_code=200, content=jsonable_encoder(response))


@auth_router.post("/refresh", status_code=status.HTTP_200_OK)
async def refresh(refresh_token: str):
    """Refreshes user token"""

    # get user id from token
    # perform logic to check if user is active
    # perform logic to check if user is banned

    # generate user tokens
    access_tk, refresh_tk = user_service.refresh_access_token(
        current_refresh_token=refresh_token
    )

    # perform other logic such as setting cookies
    # loging the event in audit logs

    return JsonResponseDict(
        message="Token refreshed",
        status_code=200,
        data={
            "access": access_tk,
            "refresh": refresh_tk,
        },
    )


# PASSWORD RELATED ENDPOINTS
@auth_router.post(
    "/forgot-password",
    summary="Endpoint to request password reset",
    status_code=status.HTTP_200_OK,
)
async def forgot_password(email: str):
    """Request password reset"""
    pass


@auth_router.post(
    "/reset-password/{token}",
    summary="Endpoint to reset user password",
    status_code=status.HTTP_200_OK,
)
async def reset_password(token: str, new_password: str):
    """Reset user password"""
    pass


@auth_router.post(
    "/change-password",
    summary="Endpoint to change user password",
    status_code=status.HTTP_200_OK,
)
async def change_password(old_password: str, new_password: str):
    """Change user password"""
    pass


# EMAIL VERIFICATION


@auth_router.post(
    "/verify-email/{token}",
    summary="Endpoint to verify user email.",
    status_code=status.HTTP_200_OK,
)
async def verify_email(token: str):
    """Verifies user email"""

    # perform logic to verify email
    # loging the event in audit logs

    return JsonResponseDict(
        message="Email verified",
        status_code=200,
    )


@auth_router.post(
    "/resend-verification-email",
    summary="Endpoint to resend email verification",
    status_code=status.HTTP_200_OK,
)
async def resend_verification(token: str):
    """Verifies user email"""

    # perform logic to resend email verification
    # loging the event in audit logs

    return JsonResponseDict(
        message="Email verified",
        status_code=200,
    )
