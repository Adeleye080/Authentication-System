from pydantic import (
    BaseModel,
    EmailStr,
    StringConstraints,
    Field,
    ConfigDict,
    model_validator,
)
from datetime import datetime
from typing import Annotated, List, Union, Optional
import re
import dns.resolver
from email_validator import validate_email, EmailNotValidError  # type: ignore
from enum import Enum as PyEnum


PASSWORD_REGEX = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%&*?_~-]).{8,}$")
UUID_REGEX = r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$"


def validate_mx_record(domain: str):
    """
    Validate mx records for email
    """
    # try:
    #     # Try to resolve the MX record for the domain
    #     mx_records = dns.resolver.resolve(domain, "MX")
    #     return True if mx_records else False
    # except dns.resolver.NoAnswer:
    #     return False
    # except dns.resolver.NXDOMAIN:
    #     return False
    # except Exception:
    #     return False
    return True


class LoginSource(str, PyEnum):
    """Login sources"""

    PASSWORD = "password"
    GOOGLE = "google"
    MAGICLINK = "magiclink"
    FACEBOOK = "facebook"
    GITHUB = "github"
    TWITTER = "twitter"


class UserResponseModel(BaseModel):
    """Auth User model"""

    id: str
    email: EmailStr
    recovery_email: Optional[EmailStr]
    is_active: bool = False
    is_verified: bool = False
    is_deleted: bool = False
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime] = None
    login_source: Optional[LoginSource] = None

    class Config:
        from_attributes = True


class UserUpdateSchema(BaseModel):
    """user update schema for user"""

    recovery_email: EmailStr


class UserCreate(BaseModel):
    """Schema to create a user"""

    email: EmailStr = "user@AuthSystem.com"
    password: Annotated[
        str, StringConstraints(min_length=8, max_length=64, strip_whitespace=True)
    ] = "AuthUser12@"
    confirm_password: Annotated[
        str,
        StringConstraints(min_length=8, max_length=64, strip_whitespace=True),
        Field(exclude=True),  # exclude confirm_password field
    ] = "AuthUser12@"

    @model_validator(mode="before")
    @classmethod
    def validate_password(cls, values: dict):
        """
        Validates passwords and email.
        """
        password = values.get("password")
        confirm_password = values.get("confirm_password")
        email = values.get("email")

        # Ensure password is provided
        if not password:
            raise ValueError("Password is required")

        # Validate password using regex
        if not PASSWORD_REGEX.match(password):
            raise ValueError(
                "Password must be at least 8 characters long and include "
                "one lowercase letter, one uppercase letter, one digit, "
                "and one special character (!@#$%&*?_~-)."
            )

        # Confirm password validation
        if not confirm_password:
            raise ValueError("Confirm password is required")
        if password != confirm_password:
            raise ValueError("Passwords do not match")

        # Validate email
        try:
            email_info = validate_email(email, check_deliverability=True)
            domain = email_info.domain

            if domain.count(".com") > 1:
                raise ValueError("Email address contains multiple '.com' endings.")

            if not validate_mx_record(domain):
                raise ValueError("Email is invalid")

        except EmailNotValidError as exc:
            raise ValueError(f"Invalid email: {exc}") from exc
        except Exception as exc:
            raise ValueError(f"Email validation error: {exc}") from exc

        return values


class UserID(BaseModel):
    """User ID format (String, Any UUID version)"""

    id: Annotated[
        str,
        StringConstraints(pattern=UUID_REGEX),
    ]


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserData(BaseModel):
    """
    Schema for users to be returned to superadmin
    """

    id: str
    email: EmailStr
    recovery_email: EmailStr
    is_active: bool
    is_verified: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserUpdateResponseModel(BaseModel):
    """Auth User model"""

    message: str
    status_code: int = 200
    data: UserData


class HyperMedia(BaseModel):
    """Hypermedia infos"""

    current_page: int
    per_page: int
    total_pages: int
    total: int
    count: int
    links: dict[str, str] = {"prev_page": "/?page=1", "next_page": "?page=3"}


class AllUsersResponse(BaseModel):
    """
    Schema for all users
    """

    message: str
    status_code: int
    status: str = "success"
    data: Union[List[UserData]]
    pagination: HyperMedia


class AdminCreateUserResponse(BaseModel):
    """
    Schema response for user created by admin
    """

    message: str
    status_code: int
    status: str
    data: UserData


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    totp_code: str | None = None

    @model_validator(mode="before")
    @classmethod
    def validate_password(cls, values: dict):
        """
        Validates passwords, email, and TOTP code.
        """
        if not isinstance(values, dict):
            return values

        password = values.get("password")
        email = values.get("email")
        totp_code = values.get("totp_code")

        # Ensure password is provided
        if not password:
            raise ValueError("Password is required")

        # Validate password using regex
        if not PASSWORD_REGEX.match(password):
            raise ValueError(
                "Password must be at least 8 characters long and include "
                "one lowercase letter, one uppercase letter, one digit, "
                "and one special character (!@#$%&*?_~-)."
            )

        # Validate email
        try:
            email_info = validate_email(email, check_deliverability=True)
            domain = email_info.domain

            if domain.count(".com") > 1:
                raise ValueError("Email address contains multiple '.com' endings.")

            if not validate_mx_record(domain):
                raise ValueError("Email is invalid")

        except EmailNotValidError as exc:
            raise ValueError(f"Invalid email: {exc}") from exc
        except Exception as exc:
            raise ValueError(f"Email validation error: {exc}") from exc

        # Validate TOTP code if provided
        if totp_code:
            from api.v1.schemas.totp_device import TOTPTokenSchema

            if not TOTPTokenSchema.validate_totp_code(totp_code):
                raise ValueError("TOTP code must be a 6-digit number")

        return values


class LoginToken(BaseModel):
    """User Tokens"""

    acesss_token: str
    refresh_token: str
    scheme: str


class LoginDataSchema(BaseModel):
    """data schema to return during login"""

    tokens: LoginToken
    profile: UserData


class LoginResponseModel(BaseModel):
    """
    Schema for successful login
    """

    status: str
    status_code: int = 200
    message: str
    data: LoginDataSchema


class ChangePasswordSchema(BaseModel):
    """Schema for changing password of a user"""

    old_password: Annotated[
        Optional[str],
        StringConstraints(min_length=8, max_length=64, strip_whitespace=True),
    ] = None

    new_password: Annotated[
        str, StringConstraints(min_length=8, max_length=64, strip_whitespace=True)
    ]

    confirm_new_password: Annotated[
        str, StringConstraints(min_length=8, max_length=64, strip_whitespace=True)
    ]

    @model_validator(mode="before")
    @classmethod
    def validate_password(cls, values: dict):
        """
        Validates old and new passwords.
        """
        if not isinstance(values, dict):
            return values

        old_password = values.get("old_password")
        new_password = values.get("new_password")
        confirm_new_password = values.get("confirm_new_password")

        # Handle empty old_password
        if old_password is not None and old_password.strip() == "":
            values["old_password"] = None

        # Validate old_password if provided
        if old_password and not PASSWORD_REGEX.match(old_password):
            raise ValueError(
                "Old password must be at least 8 characters long and include "
                "one lowercase letter, one uppercase letter, one digit, "
                "and one special character (!@#$%&*?_~-)."
            )

        # Validate new_password
        if not PASSWORD_REGEX.match(new_password):
            raise ValueError(
                "New password must be at least 8 characters long and include "
                "one lowercase letter, one uppercase letter, one digit, "
                "and one special character (!@#$%&*?_~-)."
            )

        # Ensure new_password and confirm_new_password match
        if new_password != confirm_new_password:
            raise ValueError("New password and confirm new password must match")

        return values


class RoleEnum(str, PyEnum):
    ADMIN = "admin"
    USER = "user"
    MODERATOR = "moderator"


class AccessTokenData(BaseModel):
    """schema for jwt access token data"""

    id: str
    email: EmailStr = None


class DeactivateUserSchema(BaseModel):
    """Schema for deactivating a user"""

    reason: Optional[str] = None
    confirmation: bool
