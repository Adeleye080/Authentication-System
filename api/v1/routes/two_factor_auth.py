from fastapi import APIRouter, Depends, HTTPException, status, Request, BackgroundTasks
from api.v1.services import (
    user_service,
    totp_service,
    audit_log_service,
    devices_service,
)
from api.utils.json_response import JsonResponseDict
from api.utils.responses import auth_response
from api.utils.user_device_agent import get_client_ip, get_device_info
from api.utils.settings import settings
from api.v1.models.user import User
from db.database import get_db
from sqlalchemy.orm import Session
from api.v1.schemas.auth import TOTPVerificationRequest
from api.v1.schemas.user import LoginResponseModel
from api.v1.schemas.auth import (
    Completed2FASetupResponse,
    SMSAndEMAILOTPVerificationRequest,
    SMSAndEmailOTPCodeRequest,
    Disable2FARequest,
)
from api.v1.schemas.audit_logs import (
    AuditLogCreate,
    AuditLogEventEnum,
    AuditLogStatuses,
)
from datetime import datetime as dt


two_factor_auth_router = APIRouter(tags=["2FA"], prefix="/2fa")


# rate limit to 5 or 2 requests per day
@two_factor_auth_router.post("/totp/enable", status_code=status.HTTP_200_OK)
def enable_totp(
    user: User = Depends(user_service.get_current_user),
    db: Session = Depends(get_db),
):
    """Enables 2FA for user"""

    user_service.perform_user_check(user=user)

    try:
        otpauth_url, otp_qrcode = totp_service.create(
            db=db,
            user_id=user.id,
            user_email=user.email,
        )
    except HTTPException as e:
        print(e)
        return JsonResponseDict(
            status_code=e.status_code,
            message=e.detail,
        )

    return JsonResponseDict(
        message="Successfully enabled 2fa",
        status_code=status.HTTP_200_OK,
        data={"otpauth_url": otpauth_url, "qrcode": otp_qrcode},
    )


@two_factor_auth_router.post("/totp/disable", status_code=status.HTTP_200_OK)
def disable_totp(
    request_data: Disable2FARequest,
    user: User = Depends(user_service.get_current_user),
    db: Session = Depends(get_db),
):
    """Disables 2FA for user"""

    if not user_service.verify_password(
        password=request_data.password, hash=user.password
    ):
        return JsonResponseDict(
            status_code=status.HTTP_403_FORBIDDEN,
            message="Wrong password",
            status="failed",
        )
    user_service.perform_user_check(user=user)
    try:
        totp_service.disable_totp(db=db, user_id=user.id)
    except HTTPException as e:
        print(e)
        return JsonResponseDict(
            status_code=e.status_code, message=e.detail, status="failed"
        )

    return JsonResponseDict(
        message="Successfully disabled 2fa", status_code=status.HTTP_200_OK
    )


@two_factor_auth_router.post(
    "/totp/verify",
    status_code=status.HTTP_200_OK,
    response_model=LoginResponseModel,
    responses={
        201: {
            "model": Completed2FASetupResponse,
            "description": "2FA device created and setup complete",
        }
    },
)
async def verify_totp(
    data: TOTPVerificationRequest,
    request: Request,
    bgt: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Verifies Authenticator app generated TOTP code for user login or completes TOTP(2FA) setup if user already have OTP device.

    - **email**: email of user account to setup or verify 2fa
    - **otp**: OTP code to verify
    - **temp_code:** temporary code to verify user identity. supply if it is a login attempt
    """

    user = user_service.fetch(db=db, email=data.email)

    if user.totp_device and not user.totp_device.confirmed:
        # user first attempt, complete 2fa setup
        totp_service.verify_token(
            db=db,
            user_id=user.id,
            schema=data.otp,
            extra_action="enable",
            totp_device=user.totp_device,
        )
        # Notify user of success 2fa completion
        # log to audit

        return JsonResponseDict(
            message="TOTP setup complete", status_code=status.HTTP_201_CREATED
        )
    else:
        # verifiy token for login
        totp_service.check_2fa_status_and_verify(
            db=db, user_id=user.id, schema=data.otp, totp_device=user.totp_device
        )

        # verify user temporary login token
        user_id = user_service.decrypt_and_validate_temp_login_token(
            token=data.temp_code, current_ip=get_client_ip(request)
        )

        if user.id != user_id:
            # log to audit
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Wrong temporary login token",
            )

        access_token = user_service.create_access_token(user_obj=user, db=db)
        refresh_token = user_service.create_refresh_token(db=db, user_id=user.id)

        user.email  # load object attrs
        user.login_initiated = False
        user.save(db=db)

        # save user device info
        device_info = await get_device_info(request)
        if device_info:
            devices_service.create_with_bgt(
                db=db, owner=user, device_info=device_info, bgt=bgt
            )

        response = auth_response(
            status="success",
            status_code=200,
            message="Login successful",
            user_data=user.to_dict(),
            refresh_token=refresh_token,
            access_token=access_token,
        )

        if settings.ALLOW_AUTH_COOKIES:
            response.set_cookie(
                key="access_token",
                value=access_token,
                httponly=True,
                secure=settings.AUTH_SECURE_COOKIES,
                samesite=settings.AUTH_SAME_SITE,
                expires=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
            )

            response.set_cookie(
                key="refresh_token",
                value=refresh_token,
                httponly=True,
                secure=settings.AUTH_SECURE_COOKIES,
                samesite=settings.AUTH_SAME_SITE,
                expires=settings.JWT_REFRESH_EXPIRY,
            )

        # log to audit
        audit_log_service.log(
            db=db,
            background_task=bgt,
            schema=AuditLogCreate(
                user_id=user.id,
                event=AuditLogEventEnum.LOGIN,
                description="user logged in with 2FA using TOTP",
                status=AuditLogStatuses.SUCCESS,
                ip_address=device_info.get("ip_address"),
                user_agent=device_info.get("user_agent"),
            ),
        )

        return response


@two_factor_auth_router.post(
    "/sms/request-otp",
    summary="Send OTP code via SMS",
    status_code=status.HTTP_200_OK,
)
async def request_email_sms_otp_code(
    request_data: SMSAndEmailOTPCodeRequest, db: Session = Depends(get_db)
):
    """
    Sends OTP code to user via email or SMS to complete user login. \n
    Serves as a backup for Authenticator app.\n
    Not for Authenticator app generated OTP code.
    """

    if request_data.email:
        user = user_service.fetch(db=db, email=request_data.email)

    # generate OTP code, save it and send to user

    pass


@two_factor_auth_router.post(
    "/sms/verify-otp",
    summary="Verify OTP code sent to user via email or SMS",
    status_code=status.HTTP_200_OK,
)
def verify_email_sms_otp_code(request_data: SMSAndEMAILOTPVerificationRequest):
    """
    Verifies OTP code sent to user via email or SMS.\n
    Not for Authenticator app generated OTP code.
    """
    pass
