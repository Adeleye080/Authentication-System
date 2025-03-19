from cryptography.fernet import Fernet
from decouple import config
import pyotp
from typing import ByteString


ENCRYPTER_SECRET_KEY = config(
    "ENCRYPTER_SECRET_KEY", cast=ByteString, default=b"some-secure-byte-encoded"
)  # This should be securely stored
cipher = Fernet(ENCRYPTER_SECRET_KEY)


def encrypt_totp_secret(secret: str) -> str:
    """Encrypts a TOTP secret"""
    return cipher.encrypt(secret.encode()).decode()


def decrypt_totp_secret(encrypted_secret: str) -> str:
    """Decrypts a TOTP secret"""
    return cipher.decrypt(encrypted_secret.encode()).decode()
