from fastapi import APIRouter, Depends, HTTPException, status
from api.utils.validators import check_model_existence
from api.v1.services import user_service
from api.utils.json_response import JsonResponseDict


two_factor_auth_router = APIRouter(tags=["2FA"], prefix="/2fa")


@two_factor_auth_router.post("/enable", status_code=status.HTTP_200_OK)
def enable_2fa():
    """Enables 2FA for user"""

    user = user_service.get_current_user()
    print(user)
    print(user.to_dict())

    try:
        user_service.perform_user_check(user=user)
    except HTTPException as e:
        print(e)
        return JsonResponseDict(
            status_code=e.status_code,
            message="Error enabling 2FA",
            error=e.detail,
        )
    pass


@two_factor_auth_router.post("/disable", status_code=status.HTTP_200_OK)
def disable_2fa():
    """Disables 2FA for user"""

    pass


@two_factor_auth_router.post("/verify", status_code=status.HTTP_200_OK)
def verify_2fa():
    """Verifies 2FA for user"""
    pass


@two_factor_auth_router.post(
    "/send-code",
    summary="Send TOTP code via user preferred method",
    status_code=status.HTTP_200_OK,
)
def send_totp_code():
    """Sends TOTP code to user"""
    pass


@two_factor_auth_router.post(
    "/qrcode",
    summary="TOTP QR code for authenticator app",
    status_code=status.HTTP_200_OK,
)
def send_totp_code():
    """Sends TOTP code to user"""
    pass
