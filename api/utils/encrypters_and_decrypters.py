from cryptography.fernet import Fernet
from decouple import config
import pyotp
from pydantic import EmailStr
from api.utils.settings import settings
from fastapi import HTTPException, status
from datetime import datetime, timedelta, timezone
import json
import base64


cipher_key = settings.ENCRYPTER_SECRET_KEY.encode()
cipher_suite = Fernet(cipher_key)


def encrypt_totp_secret(secret: str) -> str:
    """Encrypts a TOTP secret"""

    return cipher_suite.encrypt(secret.encode()).decode()


def decrypt_totp_secret(encrypted_secret: str) -> str:
    """Decrypts a TOTP secret"""

    return cipher_suite.decrypt(encrypted_secret.encode()).decode()


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

        assert "email" in decrypted_dict, "Token is missing important part"
        assert "expire" in decrypted_dict, "Token is missing important part"

    except AssertionError as ase:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ase))
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
    Generate magic link token for user login.
    Default validity is 10mins
    """

    token_data = f"{email}-{(datetime.now(timezone.utc) + timedelta(minutes=validity)).timestamp()}"

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
        email, expiry_timestamp = decrypted_data.split("-")

        # Validate the email and expiry timestamp
        print(email, expiry_timestamp)
        assert "@" in email, "Token is malformed."
        assert expiry_timestamp is not None, "Token is missing important part"

    except AssertionError as ase:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ase))
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
