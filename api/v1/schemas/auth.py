from pydantic import BaseModel, Field, EmailStr, model_validator
from typing import Annotated, Optional


class TOTPDeviceRequestSchema(BaseModel):
    """Schema for TOTP Device creation request"""

    user_id: str
    # secret: str


class TOTPDeviceResponseSchema(BaseModel):
    """Schema for TOTP Device creation response"""

    # secret: str
    otpauth_url: str
    qrcode_base64: str


class TOTPDeviceDataSchema(BaseModel):
    """Schema for representing TOTP Device data"""

    user_id: str
    confirmed: bool


class TOTPTokenSchema(BaseModel):
    """Schema for validating TOTP token provided by the user"""

    totp_token: Annotated[str, Field(min_length=6, max_length=6)]

    @classmethod
    def validate_totp_code(cls, code: str) -> bool:
        """Validates that the TOTP code is a 6-digit number"""

        if not code or len(code) != 6:
            return False
        try:
            int(code)
            return True
        except ValueError:
            return False


class TOTPVerificationRequest(BaseModel):
    email: EmailStr = Field(...)
    otp: str = Field(...)
    temp_code: Optional[str] = Field(
        None,
        description="Temporary login token to verify user identity and tracks user.",
    )

    @model_validator(mode="before")
    @classmethod
    def validate_otp(cls, values: dict):
        """Validate TOTP and temp_code if provided"""

        if not isinstance(values, dict):
            return values

        totp_code = values.get("otp", None)
        temp_code = values.get("temp_code", None)
        if totp_code:

            if not TOTPTokenSchema.validate_totp_code(totp_code):
                raise ValueError("TOTP code must be a 6-digit number")

        if not temp_code or temp_code == "string":
            temp_code = None

        return values

    @model_validator(mode="before")
    @classmethod
    def validate_email_username_inputs(cls, values: dict):
        """Ensure email is given."""

        email = values.get("email", None)

        if not email:
            raise ValueError("email must be given")

        return values


class Completed2FASetupResponse(BaseModel):
    """Schema for completed 2FA setup"""

    message: str = "2FA setup complete"
    status_code: int = 201
    status: str = "success"


class SMSOTPVerificationRequest(BaseModel):
    email: Optional[EmailStr] = Field(...)
    otp: str = Field(..., description="6-digit OTP code received via SMS")
    temp_code: Optional[str] = Field(
        ..., description="Temporary login token to verify user identity, tracks user."
    )

    @model_validator(mode="before")
    @classmethod
    def validate_otp(cls, values: dict):
        """Validate TOTP code if provided"""

        if not isinstance(values, dict):
            return values

        otp_code = values.get("otp", None)
        if otp_code:

            if not otp_code or len(otp_code) != 6:
                raise ValueError("OTP code must be given and must be 6 digits")
            try:
                int(otp_code)
            except Exception:
                raise ValueError("OTP code must be a 6-digit number")

        return values

    @model_validator(mode="before")
    @classmethod
    def validate_email_username_inputs(cls, values: dict):
        """Validates email given."""

        email = values.get("email", None)

        if not email:
            raise ValueError("email must be given")

        return values


class SMSOTPCodeRequest(BaseModel):
    """schema for OTP code request"""

    email: EmailStr = Field(...)

    @model_validator(mode="before")
    @classmethod
    def validate_email_username_inputs(cls, values: dict):
        """Validates email and username inputs, ensures one of the 2 must be given."""

        email = values.get("email", None)

        if not email:
            raise ValueError("email must be given")

        return values


class Disable2FARequest(BaseModel):
    """Schema for disabling 2FA"""

    password: str = Field(..., description="Password of the user to disable 2FA")


class VerifyEmailOTPRequest(BaseModel):
    """Schema for verifying email with OTP"""

    temp_token: str = Field(
        ...,
        description="Temporary login token to verify user identity and tracks user.",
    )
    otp: str = Field(..., description="6-digit OTP code for verification")

    @model_validator(mode="before")
    @classmethod
    def validate_otp(cls, values: dict):
        """Validate OTP code format"""

        otp_code = values.get("otp", None)
        if not otp_code or len(str(otp_code)) != 6:
            raise ValueError("OTP code must be a 6-digit number")

        try:
            int(otp_code)
        except ValueError:
            raise ValueError("OTP code must be a 6-digit number")

        return values
