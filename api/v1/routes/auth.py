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

from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import logging
from sqlalchemy.orm import Session
from db.database import get_db
from api.v1.schemas.user import (
    UserLogin,
    LoginResponseModel,
    SwaggerLoginToken,
    EmailStr,
    PasswordChangeRequest,
    PasswordResetRequest,
    MagicLinkToken,
    MagicLinkRequest,
)
from api.v1.schemas.audit_logs import (
    AuditLogCreate,
    AuditLogEventEnum,
    AuditLogStatuses,
)
from api.v1.schemas.user import GeneralResponse, RefreshTokenRequest
from api.utils.json_response import JsonResponseDict
from api.utils.settings import settings
from api.utils.responses import auth_response
from api.utils.user_device_agent import get_device_info, get_client_ip
from api.v1.models.user import User
from api.v1.services import (
    user_service,
    audit_log_service,
    devices_service,
    notification_service,
    geoip_service,
)


auth_router = APIRouter(tags=["Auth"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/swagger-login")
logger = logging.getLogger(__name__)


@auth_router.post(
    "/login", response_model=LoginResponseModel, status_code=status.HTTP_200_OK
)
async def login(
    request: Request,
    data: UserLogin,
    bgt: BackgroundTasks,
    db: Session = Depends(get_db),
    validate_request_country_in_blacklist=Depends(
        geoip_service.blacklisted_country_dependency_check
    ),
):
    """Logs client in

    **Client may be regular users, moderator of admin
    **This endpoint is used to log in users using their email and password.
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

    # check user 2fa status
    if user.totp_device and user.totp_device.confirmed:
        temp_token = user_service.create_and_encrypt_temp_login_token(
            user_id=user.id, ip_address=get_client_ip(request)
        )
        user.login_initiated = True
        user.save(db=db)
        return JsonResponseDict(
            message="Login initiated, Please provide OTP and your temporary token to complete login",
            status_code=status.HTTP_202_ACCEPTED,
            status="pending",
            data={"requires_2fa": True, "temp_token": temp_token},
        )

    try:
        # generate user tokens
        user_access_token = user_service.create_access_token(user_obj=user, db=db)
        user_refresh_token = user_service.create_refresh_token(db=db, user_id=user.id)

    except HTTPException as exc:
        return JsonResponseDict(
            status="failed",
            message=exc.detail,
            status_code=exc.status_code,
        )

    user.email  # load object attrs

    response = auth_response(
        status="success",
        status_code=200,
        message="Login was successful",
        user_data=user.to_dict(),
        refresh_token=user_refresh_token,
        access_token=user_access_token,
    )

    # set cookies
    if settings.ALLOW_AUTH_COOKIES:
        response.set_cookie(
            key="access_token",
            value=user_access_token,
            httponly=True,
            secure=settings.AUTH_SECURE_COOKIES,
            samesite=settings.AUTH_SAME_SITE,
            expires=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        )

        response.set_cookie(
            key="refresh_token",
            value=user_refresh_token,
            httponly=True,
            secure=settings.AUTH_SECURE_COOKIES,
            samesite=settings.AUTH_SAME_SITE,
            expires=settings.JWT_REFRESH_EXPIRY,
        )

    # audit log
    device_info = await get_device_info(request)
    audit_log_service.log(
        db=db,
        background_task=bgt,
        schema=AuditLogCreate(
            user_id=user.id,
            event=AuditLogEventEnum.LOGIN,
            description="user logged in with password",
            status=AuditLogStatuses.SUCCESS,
            ip_address=device_info.get("ip_address"),
            user_agent=device_info.get("user_agent"),
        ),
    )

    return response


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
        access_token = user_service.create_access_token(user_obj=user, db=db)

    return SwaggerLoginToken(access_token=access_token, token_type="bearer")


@auth_router.post(
    "/magic-link/request",
    response_model=GeneralResponse,
    status_code=status.HTTP_200_OK,
)
async def request_magic_link_login(
    request: Request,
    bgt: BackgroundTasks,
    email: MagicLinkRequest,
    db: Session = Depends(get_db),
):
    """Send magic link to user"""

    user = user_service.fetch(db, email.email)
    user_service.perform_user_check(user=user)

    # send magic link mail to user
    link = notification_service.send_magic_link_mail(user=user, bgt=bgt)

    # loging the event in audit logs
    device_info = await get_device_info(request)
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
    )


@auth_router.post(
    "/magic-link/verify",
    response_model=LoginResponseModel,
    status_code=status.HTTP_200_OK,
)
async def magic_link_login(
    schema: MagicLinkToken,
    bgt: BackgroundTasks,
    request: Request,
    db: Session = Depends(get_db),
):
    """verifies magic link token and logs user in"""

    user = user_service.authenticate_user_with_magic_link(db, schema.token)
    # generate user tokens
    user_access_token = user_service.create_access_token(user_obj=user, db=db)
    user_refresh_token = user_service.create_refresh_token(db=db, user_id=user.id)

    user.email  # essential to load the user object attributes.

    response = auth_response(
        status="success",
        status_code=200,
        message="Login was successful",
        user_data=user.to_dict(),
        refresh_token=user_refresh_token,
        access_token=user_access_token,
    )

    if settings.ALLOW_AUTH_COOKIES:
        response.set_cookie(
            key="access_token",
            value=user_access_token,
            httponly=True,
            secure=settings.AUTH_SECURE_COOKIES,
            samesite=settings.AUTH_SAME_SITE,
            expires=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        )

        response.set_cookie(
            key="refresh_token",
            value=user_refresh_token,
            httponly=True,
            secure=settings.AUTH_SECURE_COOKIES,
            samesite=settings.AUTH_SAME_SITE,
            expires=settings.JWT_REFRESH_EXPIRY,
        )

        # loging the event in audit logs
        device_info = await get_device_info(request)
        audit_log_service.log(
            db=db,
            schema=AuditLogCreate(
                user_id=user.id,
                event=AuditLogEventEnum.LOGIN,
                description="User logged in using magic link",
                status=AuditLogStatuses.SUCCESS,
                ip_address=device_info.get("ip_address", "N/A"),
                user_agent=device_info.get("user_agent", "N/A"),
            ),
            background_task=bgt,
        )

    return response


@auth_router.post("/logout", status_code=status.HTTP_200_OK)
async def logout(
    refresh_token_schema: RefreshTokenRequest, db: Session = Depends(get_db)
):
    """Logs user out of the system"""

    refresh_token = refresh_token_schema.refresh_token
    if refresh_token:
        try:
            user_service.revoke_refresh_token(db=db, token=refresh_token)
        except HTTPException as exc:
            return JsonResponseDict(
                message=exc.detail,
                status="failed",
                status_code=exc.status_code,
            )

        response = JsonResponseDict(
            message="Logout was successful",
            status="success",
            status_code=status.HTTP_200_OK,
        )
        if settings.ALLOW_AUTH_COOKIES:
            response.delete_cookie(key="access_token")
            response.delete_cookie(key="refresh_token")

        return response
    else:
        return JsonResponseDict(
            message="Refresh token is required",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


@auth_router.post("/refresh", status_code=status.HTTP_200_OK)
async def refresh(
    refresh_token_schema: RefreshTokenRequest,
    db: Session = Depends(get_db),
):
    """Refreshes user token"""

    new_access_token, new_refresh_token = user_service.refresh_access_token(
        db, refresh_token_schema.refresh_token
    )

    # perform other logic such as setting cookies
    # loging the event in audit logs

    return JsonResponseDict(
        message="Token refreshed",
        status="success",
        status_code=status.HTTP_200_OK,
        data={
            "access": new_access_token,
            "refresh": new_refresh_token,
        },
    )


# PASSWORD RELATED ENDPOINTS
@auth_router.post(
    "/forgot-password",
    summary="Endpoint to request password reset",
    status_code=status.HTTP_200_OK,
)
async def forgot_password(
    email: EmailStr, bgt: BackgroundTasks, db: Session = Depends(get_db)
):
    """Request password reset"""

    user = user_service.fetch(db=db, email=email)

    if user:
        notification_service.send_password_reset_mail(user=user, bgt=bgt)

    return JsonResponseDict(
        message="If that email address exists in our system, you will receive a password reset link shortly.",
        status_code=200,
    )


@auth_router.post(
    "/reset-password",
    summary="Endpoint to reset user password",
    status_code=status.HTTP_200_OK,
)
async def reset_password(
    token: str = Query(..., description="Password reset token"),
    data: PasswordResetRequest = Body(..., description="New Password"),
    db: Session = Depends(get_db),
):
    """Reset user password"""

    from api.utils.encrypters_and_decrypters import decrypt_password_reset_token

    # decrypt token
    user_email = decrypt_password_reset_token(token)

    # check if user exists
    user = user_service.fetch(db=db, email=user_email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Auth user does not exist"
        )

    # Check user status
    user_service.perform_user_check(user=user)
    # change(reset) user password
    access_token, refresh_token = user_service.change_password(
        new_password=data.new_password, user=user, db=db, mode="reset"
    )

    # send notification to user

    # loging the event in audit logs

    return JsonResponseDict(
        message="Password reset successful",
        status_code=status.HTTP_200_OK,
        data={
            "access": access_token,
            "refresh": refresh_token,
        },
    )


@auth_router.post(
    "/change-password",
    summary="Endpoint to change user password",
    status_code=status.HTTP_200_OK,
)
async def change_password(
    data: PasswordChangeRequest,
    user: User = Depends(user_service.get_current_user),
    db: Session = Depends(get_db),
):
    """Change user password"""

    # Check if user is authenticated
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not authenticated",
        )

    # change user password
    access_token, refresh_token = user_service.change_password(
        new_password=data.new_password, old_password=data.old_password, user=user, db=db
    )

    # notify user of password change

    # loging the event in audit logs

    return JsonResponseDict(
        message="Password changed successfully",
        status_code=status.HTTP_200_OK,
        data={
            "access": access_token,
            "refresh": refresh_token,
        },
    )


# EMAIL VERIFICATION ENDPOINTS


@auth_router.post(
    "/verify-email",
    summary="Endpoint to verify user email.",
    status_code=status.HTTP_200_OK,
)
async def verify_email(
    bgt: BackgroundTasks,
    request: Request,
    token: str = Query(..., description="verification token"),
    db: Session = Depends(get_db),
):
    """Verifies user email/account"""
    from api.utils.encrypters_and_decrypters import decrypt_verification_token

    user_email = decrypt_verification_token(token)

    user = user_service.fetch(db=db, email=user_email)

    # Check if user is already verified
    if user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Email is already verified."
        )

    # verify and activate user
    user.is_verified = True
    user.is_active = True
    user.save(db=db)

    # send notification to user
    notification_service.send_welcome_mail(user=user, bgt=bgt)

    # loging the event in audit logs
    device_info = await get_device_info(request)
    log_description = "User email verified"
    try:
        schema = AuditLogCreate(
            user_id=user.id,
            event=AuditLogEventEnum.VERIFY_EMAIL,
            description=log_description,
            ip_address=device_info.get("ip_address", "N/A"),
            user_agent=device_info.get("user_agent", "N/A"),
            status=AuditLogStatuses.SUCCESS,
        )
        audit_log_service.log(db=db, schema=schema, background_task=bgt)

        # log to logger
        logger.info(f"Audit Log ({user.email}) email verified")
    except Exception as exc:
        logger.info(
            f"Failed to Audit Log ({user.email}) email verification, error {exc}"
        )

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
    log_description = "User requested resend of email verification link"
    try:
        schema = AuditLogCreate(
            user_id=user.id,
            event=AuditLogEventEnum.REQUEST_VERIFICATION,
            description=log_description,
            ip_address=device_info.get("ip_address", "N/A"),
            user_agent=device_info.get("user_agent", "N/A"),
            status=AuditLogStatuses.SUCCESS,
        )
        audit_log_service.log(db=db, schema=schema, background_task=bgt)

        # log to logger
        logger.info(f"Audit Log ({user.email}) request for verification email")

    except Exception as exc:
        logger.info(
            f"Failed to Audit Log ({user.email}) request for verification email, error {exc}"
        )

    return JsonResponseDict(
        message=f"verifcation email has been sent to {user.email}",
        status_code=200,
    )
