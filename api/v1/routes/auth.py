"""
Authentication Module
Handles user login, logout and refresh token routes
"""

from typing import Annotated
from fastapi import (
    APIRouter,
    HTTPException,
    Depends,
    status,
    Request,
    BackgroundTasks,
    Query,
    Path,
    Body,
)
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import logging
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from db.database import get_db
from api.v1.schemas.user import (
    UserLogin,
    LoginResponseModel,
    SwaggerLoginToken,
    EmailStr,
)
from api.v1.schemas.audit_logs import (
    AuditLogCreate,
    AuditLogEventEnum,
    AuditLogStatuses,
)
from api.v1.schemas.user import LoginSource, GeneralResponse
from api.utils.json_response import JsonResponseDict
from api.utils.responses import auth_response
from api.utils.user_device_agent import get_device_info
from api.utils.settings import settings
from api.v1.models.user import User
from api.v1.services import (
    user_service,
    audit_log_service,
    devices_service,
    notification_service,
)
from smtp.mailing import send_mail


auth_router = APIRouter(tags=["Auth"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/swagger-login")
logger = logging.getLogger(__name__)


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
    except HTTPException as exc:
        return JsonResponseDict(
            status="failed",
            message=exc.detail,
            status_code=exc.status_code,
        )

    try:
        # generate user tokens
        user_access_token = user_service.create_access_token(user_id=user.id)
        user_refresh_token = user_service.create_refresh_token(db=db, user_id=user.id)

    except HTTPException as exc:
        return JsonResponseDict(
            status="failed",
            message=exc.detail,
            status_code=exc.status_code,
        )

    # perform other logic such as setting cookies
    # loging the event in audit logs

    user.username  # load object attrs

    return auth_response(
        status="success",
        status_code=200,
        message="Login was successful",
        user_data=user.to_dict(),
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
    "/magic-link/request",
    response_model=GeneralResponse,
    status_code=status.HTTP_200_OK,
)
async def request_magic_link_login(
    request: Request,
    bgt: BackgroundTasks,
    email: EmailStr = Body(..., description="valid user email"),
    db: Session = Depends(get_db),
):
    """Logs client in using magic link"""

    user = user_service.fetch(db, email)
    user_service.perform_user_check(user=user)

    # send magic link mail to user
    link = notification_service.send_magic_link_mail(user=user, bgt=bgt)

    # loging the event in audit logs
    device_info = await get_device_info(request)  # capture user device
    audit_log_service.log(
        db=db,
        schema=AuditLogCreate(
            user_id=user.id,
            event=AuditLogEventEnum.REQUEST_MAGIC_LINK,
            description="User requested magic link",
            status=AuditLogStatuses.SUCCESS,
            ip_address=device_info.get("ip_address"),
            user_agent=device_info.get("user_agent"),
        ),
        background_task=bgt,
    )

    return JsonResponseDict(
        message="Magic link has been sent to your email",
        status_code=status.HTTP_200_OK,
        # for testing, should be removed
        data={"magic_link": link},
    )


@auth_router.get(
    "/magic-link/verify",
    response_model=LoginResponseModel,
    status_code=status.HTTP_200_OK,
)
async def magic_link_login(
    token: str = Query(..., description="magic link token"),
    db: Session = Depends(get_db),
):
    """verifies magic link token and logs user in"""

    user = user_service.authenticate_user_with_magic_link(db, token)
    # generate user tokens
    user_access_token = user_service.create_access_token(user_id=user.id)
    user_refresh_token = user_service.create_refresh_token(db=db, user_id=user.id)

    # perform other logic such as setting cookies
    # loging the event in audit logs

    user.username  # essential to load the user object attributes. Possiblt python bug

    return auth_response(
        status="success",
        status_code=200,
        message="Login was successful",
        user_data=user.to_dict(),
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

    from jose import jwt  # type: ignore

    payload = jwt.decode(
        refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
    )

    user = User.get_by_id(id=payload.get("sub"))

    if user_service.perform_user_check(user=user):

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
async def change_password(
    old_password: str,
    new_password: str,
    user: User = Depends(user_service.get_current_user),
):
    """Change user password"""
    pass


# EMAIL VERIFICATION ENDPOINTS


@auth_router.post(
    "/verify-email",
    summary="Endpoint to verify user email.",
    status_code=status.HTTP_200_OK,
)
async def verify_email(
    token: str = Query(..., description="verification token"),
    db: Session = Depends(get_db),
):
    """Verifies user email/account"""
    from api.utils.encrypters_and_decrypters import decrypt_verification_token  # type: ignore

    user_email = decrypt_verification_token(token)

    user = user_service.fetch(db=db, email=user_email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User does not exist"
        )

    # Check if user is already verified
    if user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Email is already verified."
        )

    # verify and activate user
    user.is_verified = True
    user.is_active = True
    user.save(db=db)

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
async def resend_verification(
    request: Request,
    bgt: BackgroundTasks,
    email: EmailStr = Query(..., description="User Email"),
    db: Session = Depends(get_db),
):
    """Request for new user email verification"""

    # perform logic to resend email verification
    user = user_service.fetch(db=db, email=email)

    # Check if user is already verified
    if user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Email is already verified."
        )

    # send verification mail to user
    notification_service.send_verify_email_mail(user=user, bgt=bgt)

    # capture user device
    device_info = await get_device_info(request)

    # loging the event in audit logs
    log_description = "User requested email verification link"
    try:
        schema = AuditLogCreate(
            user_id=user.id,
            event=AuditLogEventEnum.REQUEST_VERIFICATION,
            description=log_description,
            ip_address=device_info.get("ip_address"),
            user_agent=device_info.get("user_agent"),
            status=AuditLogStatuses.SUCCESS,
        )
        audit_log_service.log(db=db, schema=schema, background_task=bgt)

        # log to logger
        logger.info(
            f"Audit Log {user.username} ({user.email}) request for verification email"
        )

    except Exception as exc:
        logger.info(
            f"Failed to Audit Log {user.username} ({user.email}) request for verification email, error {exc}"
        )

    return JsonResponseDict(
        message=f"verifcation email has been sent to {user.email}",
        status_code=200,
    )
