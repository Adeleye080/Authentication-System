from sqlalchemy.orm import Session
from api.utils.settings import settings
from fastapi import HTTPException, status
from api.v1.models.totp_device import TOTPDevice
import pyotp
import qrcode
import io
import base64
from typing import Tuple
from sqlalchemy.exc import SQLAlchemyError
from pydantic import EmailStr
from datetime import datetime, timezone


class TOTPService:
    """
    Service class providing TOTP functionality for two-factor authentication.

    This service class handles all operations related to TOTP devices, including creating TOTP devices,
    generating secrets, otpauth URLs, QR codes, and verifying OTP tokens.
    """

    def create(
        self,
        db: Session,
        user_id: str,
        user_email: EmailStr,
    ) -> Tuple[str, str]:
        """Create a new TOTP device for the given user ID.
        If a TOTP device already exists for the user and `delete_existing` is `False`, an HTTPException is raised.

        :param db: Database session
        :param user_id: User ID to create the TOTP device for

        :return: Tuple containing the otpauth URL and base64-encoded QR code
        :raises HTTPException: If a TOTP device already exists for the user and 'delete_existing' is `False` or if there is a database error
        """
        from api.utils.encrypters_and_decrypters import encrypt_totp_secret

        try:
            totp_device_exist = self.fetch(db=db, user_id=user_id)

            if totp_device_exist:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="totp device for this user already exists",
                )

            plaintext_secret = self.generate_secret()
            encryted_secret = encrypt_totp_secret(secret=plaintext_secret)
            totp_device = TOTPDevice(user_id=user_id, secret=encryted_secret)
            db.add(totp_device)
            db.commit()
            db.refresh(totp_device)

            # Generate otpauth URL and QR code
            otpauth_url = self.generate_otpauth_url(
                secret=plaintext_secret,
                user_email=user_email if user_email else user_id,
                app_name=settings.APP_NAME,
            )
            qrcode_base64 = self.generate_qrcode(otpauth_url=otpauth_url)

            return (otpauth_url, qrcode_base64)
        except SQLAlchemyError as e:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Database error: {str(e)}",
            )
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error creating TOTP device: {str(e)}",
            )

    def fetch(self, db: Session, user_id: str) -> TOTPDevice | None:
        """Fetch a TOTP device by corresponding user id"""

        try:
            return db.query(TOTPDevice).filter(TOTPDevice.user_id == user_id).first()
        except SQLAlchemyError as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Database error when fetching TOTP device: {str(e)}",
            )

    def generate_secret(self) -> str:
        """Generate a unique secret for the TOTP device"""

        try:
            return pyotp.random_base32()
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error generating TOTP secret: {str(e)}",
            )

    def generate_otpauth_url(self, secret: str, user_email: str, app_name: str) -> str:
        """Generate otpauth URL for the authenticator app"""

        try:
            totp = pyotp.TOTP(secret)
            return totp.provisioning_uri(name=user_email, issuer_name=app_name)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error generating otpauth URL: {str(e)}",
            )

    def generate_qrcode(self, otpauth_url: str) -> str:
        """Generate a QR code for the otpauth URL and returns it as base64 string"""

        try:
            qr = qrcode.make(otpauth_url)
            buffer = io.BytesIO()
            qr.save(buffer, format="PNG")
            return base64.b64encode(buffer.getvalue()).decode("utf-8")
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error generating QR code: {str(e)}",
            )

    def verify_token(
        self,
        db: Session,
        user_id: str,
        schema: str,
        valid_window: int = 1,
        extra_action: str | None = None,
        totp_device: TOTPDevice | None = None,
    ) -> bool:
        """
        Verify TOTP code with an optional valid time window for drift.
        Optionally handle enabling/disabling of TOTP devices.

        :param db: Database session
        :param user_id: User ID to verify the TOTP code for
        :param schema: TOTP code to verify
        :param valid_window: Optional time window in seconds for code verification
        :param extra_action: Optional action to enable/disable TOTP device
        :param totp_device: Optional TOTP device object to use for verification
        :return: True if verification is successful, otherwise raises HTTPException
        """

        if not totp_device:
            totp_device = self.fetch(db=db, user_id=user_id)
        if not totp_device:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA is not set up for this user",
            )
        try:
            from api.utils.encrypters_and_decrypters import decrypt_totp_secret

            if extra_action and extra_action not in ["enable", "disable"]:
                raise ValueError("extraction action must be 'enable' or 'disable'")

            totp = pyotp.TOTP(decrypt_totp_secret(totp_device.secret))
            if not totp.verify(schema, valid_window=valid_window):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid TOTP code"
                )

        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error verifying totp code: {str(e)}",
            )

        # Handle enable/disable actions
        try:
            if extra_action is not None:
                if extra_action == "enable":
                    totp_device.confirmed = True
                elif extra_action == "disable":
                    totp_device.confirmed = False

            # commit last_used and extra action
            totp_device.last_used = datetime.now(timezone.utc)
            db.add(totp_device)
            db.commit()
        except SQLAlchemyError as e:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Database error: {str(e)}",
            )

        return True

    def check_2fa_status_and_verify(
        self,
        db: Session,
        user_id: str,
        schema: str | None = None,
        totp_device: TOTPDevice | None = None,
    ):
        """Check if user has 2FA enabled and verify code if True"""

        if not totp_device:
            totp_device = self.fetch(db, user_id)
        if totp_device and hasattr(totp_device, "confirmed"):
            if totp_device.confirmed and not schema:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="2FA is enabled for this user. Provide a valid TOTP code.",
                )
            elif not totp_device.confirmed and schema:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="2FA is not enabled for this user. Proceed to enable 2FA device.",
                )
            elif totp_device.confirmed and schema:
                return self.verify_token(db, user_id, schema, totp_device=totp_device)

    def disable_totp(self, db: Session, user_id: str) -> None:
        """Disable TOTP device for the given user ID"""

        try:
            totp_device = self.fetch(db=db, user_id=user_id)
            if not totp_device:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="2fa not enabled",
                )
            db.delete(totp_device)
            db.commit()
        except SQLAlchemyError as e:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Database error when disabling TOTP device: {str(e)}",
            )
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error disabling TOTP device: {str(e)}",
            )
