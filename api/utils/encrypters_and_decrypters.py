from cryptography.fernet import Fernet
from pydantic import EmailStr
from api.utils.settings import settings
from api.utils.validators import is_email, is_uuid
from fastapi import HTTPException, status
from datetime import datetime, timedelta, timezone
import json
import base64


cipher_key = settings.ENCRYPTER_SECRET_KEY.encode()
cipher_suite = Fernet(cipher_key)


def encrypt_totp_secret(secret: str) -> str:
    """Encrypts a TOTP secret"""

    return cipher_suite.encrypt(secret.encode())


def decrypt_totp_secret(encrypted_secret: str) -> str:
    """Decrypts a TOTP secret"""

    return cipher_suite.decrypt(encrypted_secret)


def generate_user_verification_token(user_email: EmailStr) -> str:
    """
    Generates a time based token to verify user.
    valid for 24hours
    """

    data_dict = {
        "email": user_email,
        "expire": (datetime.now(timezone.utc) + timedelta(hours=24)).timestamp(),
    }
    json_data = json.dumps(data_dict)

    encrypted_data = cipher_suite.encrypt(json_data.encode())
    encoded_encrypted_data = base64.urlsafe_b64encode(encrypted_data).decode()

    return encoded_encrypted_data


def decrypt_verification_token(token: str) -> EmailStr:
    """decrypts and validate user verification token for account verification"""

    try:
        decoded_encrypted_data = base64.urlsafe_b64decode(token)
        decrypted_data = cipher_suite.decrypt(decoded_encrypted_data).decode()
        decrypted_dict = json.loads(decrypted_data)

        if "email" not in decrypted_dict or "expire" not in decrypted_dict:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="token missing vital part",
            )

    except HTTPException as he:
        raise HTTPException(status_code=he.status_code, detail=he.detail) from he

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Token"
        )

    exipiry_timestamp = decrypted_dict.get("expire")
    current_timestamp = datetime.now(timezone.utc).timestamp()

    if current_timestamp > exipiry_timestamp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired"
        )

    return decrypted_dict.get("email")


def generate_magic_link_token(email: EmailStr, validity: int = 10):
    """
    Generate magic link token for user passwordless login.\n
    token format: email-validity-tokenType. \n
    Default validity is 10mins
    """

    token_data = f"{email}-{(datetime.now(timezone.utc) + timedelta(minutes=validity)).timestamp()}-magiclink"

    magic_link_token = base64.urlsafe_b64encode(
        cipher_suite.encrypt(token_data.encode())
    ).decode()

    return magic_link_token


def decrypt_magic_link_token(token: str) -> EmailStr:
    """
    Decrypts and validates magic link token. Returns the user email address if valid.
    """

    try:
        decoded_encrypted_data = base64.urlsafe_b64decode(token)
        decrypted_data = cipher_suite.decrypt(decoded_encrypted_data).decode()
        email, expiry_timestamp, token_type = decrypted_data.split("-")

        # Validate the email and expiry timestamp

        if token_type != "magiclink":
            raise HTTPException(status_code=400, detail="Invalid token type.")
        if not is_email(email):
            raise HTTPException(status_code=400, detail="Token is malformed.")
        if expiry_timestamp is None:
            raise HTTPException(status_code=400, detail="Token is missing timestamp.")

    except HTTPException as he:
        raise HTTPException(status_code=he.status_code, detail=he.detail) from he

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Token"
        )

    current_timestamp = datetime.now(timezone.utc).timestamp()

    if current_timestamp > float(expiry_timestamp):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired"
        )

    return email


def generate_password_reset_token(email: EmailStr, validity: int = 30) -> str:
    """
    Generate and encrypt password reset token.\n
    token format: email-validity-tokenType. \n
    Default validity is 30mins
    """

    token_data = f"{email}-{(datetime.now(timezone.utc) + timedelta(minutes=validity)).timestamp()}-passwordreset"

    password_reset_token = base64.urlsafe_b64encode(
        cipher_suite.encrypt(token_data.encode())
    ).decode()

    return password_reset_token


def decrypt_password_reset_token(token: str) -> EmailStr:
    """
    Decrypts and validates reset password token. Returns the user email address if valid.
    """

    decoded_encrypted_data = base64.urlsafe_b64decode(token)
    decrypted_data = cipher_suite.decrypt(decoded_encrypted_data).decode()
    email, expiry_timestamp, token_type = decrypted_data.split("-")

    # Validate the email and expiry timestamp

    if token_type != "passwordreset":
        raise HTTPException(status_code=400, detail="Invalid token type.")
    if not is_email(email):
        raise HTTPException(status_code=400, detail="Token is malformed.")
    if expiry_timestamp is None:
        raise HTTPException(status_code=400, detail="Token is missing timestamp.")

    current_timestamp = datetime.now(timezone.utc).timestamp()

    if current_timestamp > float(expiry_timestamp):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired"
        )

    return email


def generate_email_otp_login_temp_token(user_id: str, validity: int = 10) -> str:
    """
    Generate temporary token for email OTP login.\n
    token format: email-validity-tokenType. \n
    Default validity is 10mins
    """

    token_data = f"{user_id}:{(datetime.now(timezone.utc) + timedelta(minutes=validity)).timestamp()}:emailotp"

    temp_token = base64.urlsafe_b64encode(
        cipher_suite.encrypt(token_data.encode())
    ).decode()

    return temp_token


def decrypt_email_otp_login_temp_token(token: str) -> str:
    """
    Decrypts and validates email OTP login temporary token.
    Returns the user ID.
    """

    decoded_encrypted_data = base64.urlsafe_b64decode(token)
    decrypted_data = cipher_suite.decrypt(decoded_encrypted_data).decode()
    user_identifier, expiry_timestamp, token_type = decrypted_data.split(":")

    # Validate the email and expiry timestamp

    if token_type != "emailotp":
        raise HTTPException(status_code=400, detail="Invalid temporary token type.")
    if not is_uuid(user_identifier):
        raise HTTPException(status_code=400, detail="Temporary token is malformed.")
    if expiry_timestamp is None:
        raise HTTPException(
            status_code=400, detail="Temporary token is missing timestamp."
        )

    current_timestamp = datetime.now(timezone.utc).timestamp()

    if current_timestamp > float(expiry_timestamp):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Temporary token has expired",
        )

    return user_identifier
