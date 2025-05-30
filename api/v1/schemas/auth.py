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
    email: Optional[EmailStr] = Field(...)
    username: Optional[str] = Field(...)
    otp: str = Field(...)
    temp_code: Optional[str] = Field(
        ..., description="Temporary login token to verify user identity, tracks user."
    )

    @model_validator(mode="before")
    @classmethod
    def validate_otp(cls, values: dict):
        """Validate TOTP code if provided"""

        if not isinstance(values, dict):
            return values

        totp_code = values.get("otp", None)
        if totp_code:

            if not TOTPTokenSchema.validate_totp_code(totp_code):
                raise ValueError("TOTP code must be a 6-digit number")

        return values

    @model_validator(mode="before")
    @classmethod
    def validate_email_username_inputs(cls, values: dict):
        """Validates email and username inputs, ensures one of the 2 must be given."""

        username = values.get("username", None)
        email = values.get("email", None)

        if not username and not email:
            raise ValueError("Username or email must be given")

        return values


class Completed2FASetupResponse(BaseModel):
    """Schema for completed 2FA setup"""

    message: str = "2FA setup complete"
    status_code: int = 201
    status: str = "success"


class SMSAndEMAILOTPVerificationRequest(BaseModel):
    email: Optional[EmailStr] = Field(...)
    username: Optional[str] = Field(...)
    otp: str = Field(..., description="6-digit OTP code received via SMS or email")
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
        """Validates email and username inputs, ensures one of the 2 must be given."""

        username = values.get("username", None)
        email = values.get("email", None)

        if not username and not email:
            raise ValueError("Username or email must be given")

        return values


class SMSAndEmailOTPCodeRequest(BaseModel):
    """schema for OTP code request"""

    email: Optional[EmailStr] = Field(...)
    username: Optional[str] = Field(...)
    delivery_method: str = Field(
        ..., description="Method of OTP delivery. Can be 'sms' or 'email'."
    )

    @model_validator(mode="before")
    @classmethod
    def validate_email_username_inputs(cls, values: dict):
        """Validates email and username inputs, ensures one of the 2 must be given."""

        username = values.get("username", None)
        email = values.get("email", None)

        if not username and not email:
            raise ValueError("Username or email must be given")

        return values

    @model_validator(mode="before")
    @classmethod
    def validate_delivery_method(cls, values: dict):
        """Validates delivery method input, ensures it is either 'sms' or 'email'."""

        delivery_method = values.get("delivery_method", None)

        if delivery_method not in ["sms", "email"]:
            raise ValueError("Delivery method must be either 'sms' or 'email'")

        return values


class Disable2FARequest(BaseModel):
    """Schema for disabling 2FA"""

    password: str = Field(..., description="Password of the user to disable 2FA")
