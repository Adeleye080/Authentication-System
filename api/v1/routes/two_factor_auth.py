from fastapi import APIRouter, Depends, HTTPException, status, Request, BackgroundTasks
from api.v1.services import (
    user_service,
    totp_service,
    audit_log_service,
    devices_service,
    notification_service,
    geoip_service,
)
from api.utils.json_response import JsonResponseDict
from api.utils.responses import auth_response
from api.utils.user_device_agent import get_client_ip, get_device_info
from api.utils.user_phonenumber import get_user_phonenumber_from_user_service
from api.utils.settings import settings
from api.v1.models.user import User
from db.database import get_db
from sqlalchemy.orm import Session
from api.v1.schemas.auth import TOTPVerificationRequest
from api.v1.schemas.user import LoginResponseModel, LoginSource
from api.v1.schemas.auth import (
    Completed2FASetupResponse,
    SMSOTPVerificationRequest,
    SMSOTPCodeRequest,
    Disable2FARequest,
)
from api.v1.schemas.audit_logs import (
    AuditLogCreate,
    AuditLogEventEnum,
    AuditLogStatuses,
)
import logging


two_factor_auth_router = APIRouter(tags=["2FA"], prefix="/2fa")
logger = logging.getLogger(__name__)


# rate limit to 5 or 2 requests per day
@two_factor_auth_router.post("/totp/enable", status_code=status.HTTP_200_OK)
async def enable_totp(
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
async def disable_totp(
    request_data: Disable2FARequest,
    bgt: BackgroundTasks,
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
        return JsonResponseDict(
            status_code=e.status_code, message=e.detail, status="failed"
        )

    # notify user
    notification_service.totp_2fa_disabled_mail(user=user, bgt=bgt)

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
    device_info = await get_device_info(request)

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
        notification_service.send_2fa_setup_success_mail(user=user, bgt=bgt)
        # log to audit
        audit_log_service.log(
            db=db,
            background_task=bgt,
            schema=AuditLogCreate(
                user_id=user.id,
                event=AuditLogEventEnum.SUCCESS_2FA,
                description="User has successfully created and verified TOTP device, enabling 2fa.",
                status=AuditLogStatuses.SUCCESS,
                ip_address=device_info.get("ip_address"),
                user_agent=device_info.get("user_agent"),
            ),
        )

        return JsonResponseDict(
            message="TOTP setup complete", status_code=status.HTTP_201_CREATED
        )
    else:

        if not data.temp_code:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Login temp_code not provided.",
            )

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
            audit_log_service.log(
                db=db,
                background_task=bgt,
                schema=AuditLogCreate(
                    user_id=user.id,
                    event=AuditLogEventEnum.LOGIN,
                    description="Attempted to login with 2FA TOTP but provided wrong/invalid/malformed temporary token",
                    status=AuditLogStatuses.FAILED,
                    ip_address=device_info.get("ip_address"),
                    user_agent=device_info.get("user_agent"),
                ),
            )
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


if settings.ALLOW_SMS_AUTH and settings.USER_SERVICE_PHONE_NUMBER_URL != "0":

    @two_factor_auth_router.post(
        "/sms/request-otp",
        summary="Send OTP code via SMS",
        status_code=status.HTTP_200_OK,
    )
    async def request_sms_otp_code(
        request_data: SMSOTPCodeRequest,
        request: Request,
        bgt: BackgroundTasks,
        db: Session = Depends(get_db),
        _: None = Depends(geoip_service.blacklisted_country_dependency_check),
    ):
        """
        Sends OTP code to user via SMS to complete user login. \n
        Serves as a backup for Authenticator app.\n
        Not for Authenticator app generated OTP code.
        """

        if request_data.email:
            user = user_service.fetch(db=db, email=request_data.email)

        device_info = await get_device_info(request)

        # get user phone number
        try:
            phone_number = await get_user_phonenumber_from_user_service(
                request_data.email
            )
        except Exception as exc:
            logger.error(
                "Failed to get user phone number from the specified user service. Looks like the service is down."
            )
            audit_log_service.log(
                db=db,
                background_task=bgt,
                schema=AuditLogCreate(
                    user_id=user.id,
                    description="Failed SMS OTP request attempt",
                    status=AuditLogStatuses.FAILED,
                    event=AuditLogEventEnum.REQUEST_OTP,
                    ip_address=device_info.get("ip_address", "N/A"),
                    user_agent=device_info.get("user_agent", "N/A"),
                ),
            )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Service temporarily unavailable",
            )

        # generate OTP code, save it.
        otp_code = totp_service.generate_sms_otp_code(db=db, user_id=user.id)

        # send otp to user
        notification_service.send_sms_otp(
            number=phone_number, otp_code=otp_code, bgt=bgt
        )

        # audit log
        audit_log_service.log(
            db=db,
            background_task=bgt,
            schema=AuditLogCreate(
                user_id=user.id,
                description="User requested for OTP code via SMS",
                status=AuditLogStatuses.SUCCESS,
                event=AuditLogEventEnum.REQUEST_OTP,
                ip_address=device_info.get("ip_address", "N/A"),
                user_agent=device_info.get("user_agent", "N/A"),
            ),
        )

        return JsonResponseDict(message="OTP sent!", status_code=status.HTTP_200_OK)

    @two_factor_auth_router.post(
        "/sms/verify-otp",
        summary="Verify OTP code sent to user via email or SMS",
        status_code=status.HTTP_200_OK,
    )
    async def verify_sms_otp_code(
        data: SMSOTPVerificationRequest,
        request: Request,
        bgt: BackgroundTasks,
        db: Session = Depends(get_db),
        _: None = Depends(geoip_service.blacklisted_country_dependency_check),
    ):
        """
        Verifies OTP code sent to user via SMS.\n
        Not for Authenticator app generated OTP code.
        """

        device_info = await get_device_info(request)

        user = user_service.fetch(db=db, email=data.email)
        # check user status
        user_service.perform_user_check(user)

        # check if user initiated login process
        if not user.login_initiated:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Login process not initiated.",
            )

        # verify user temporary login token
        user_id = user_service.decrypt_and_validate_temp_login_token(
            token=data.temp_code, current_ip=get_client_ip(request)
        )

        if user.id != user_id:
            # log to audit
            audit_log_service.log(
                db=db,
                background_task=bgt,
                schema=AuditLogCreate(
                    user_id=user.id,
                    event=AuditLogEventEnum.LOGIN,
                    description="Attempted to login with SMS TOTP but provided wrong/invalid/malformed temporary token",
                    status=AuditLogStatuses.FAILED,
                    ip_address=device_info.get("ip_address"),
                    user_agent=device_info.get("user_agent"),
                ),
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Wrong temporary login token",
            )

        # verify TOTP
        totp_service.verify_sms_otp_code(db=db, code=data.otp, user_id=user_id)

        access_token = user_service.create_access_token(user_obj=user, db=db)
        refresh_token = user_service.create_refresh_token(db=db, user_id=user.id)

        user.email  # load object attrs
        user.login_initiated = False
        user.login_source = LoginSource.PASSWORD
        user.save(db=db)

        # save user device info
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
                description="user logged in with password and OTP via SMS",
                status=AuditLogStatuses.SUCCESS,
                ip_address=device_info.get("ip_address"),
                user_agent=device_info.get("user_agent"),
            ),
        )

        return response
