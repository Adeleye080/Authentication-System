from typing import Optional
from pydantic_settings import BaseSettings
from decouple import config
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    """Class to hold application's config values."""

    # company info
    COMPANY_NAME: str = config("COMPANY_NAME", cast=str, default="FastAPI Auth System")
    COMPANY_ADDRESS: str = config(
        "COMPANY_ADDRESS", cast=str, default="123, auth system, texas, USA."
    )
    COMPANY_LOGO_URL: str = config(
        "COMPANY_LOGO_URL",
        default="https://ik.imagekit.io/flwjimnel/logo.png",
    )
    COMPANY_TERMS_OF_SERVICE_URL: str = config(
        "COMPANY_TERMS_OF_SERVICE_URL", default="http://#"
    )
    COMPANY_PRIVACY_POLICY_URL: str = config(
        "COMPANY_PRIVACY_POLICY_URL", default="http://#"
    )

    WEBHOOK_URL: Optional[str] = config(
        "WEBHOOK_URL",
        default=None,
        cast=str,
    )

    # APPLICATION SPECIFIC CONFIG
    SECRET_KEY: str = config("SECRET_KEY")
    ALGORITHM: str = config("ALGORITHM")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = config("ACCESS_TOKEN_EXPIRE_MINUTES")
    APP_SERVICE_TOKEN_EXPIRE_HOUR: int = config(
        "APP_SERVICE_TOKEN_EXPIRE_HOUR", cast=int, default=5
    )
    VERIFICATION_TOKEN_EXPIRATION_TIME: int = config(
        "VERIFICATION_TOKEN_EXPIRATION_TIME", cast=int, default=600
    )  # 10 minutes
    JWT_REFRESH_EXPIRY: int = config(
        "JWT_REFRESH_EXPIRY_DAYS", cast=int, default=30
    )  # 30 days
    ALLOW_AUTH_COOKIES: bool = config("ALLOW_AUTH_COOKIES", cast=bool, default=True)
    AUTH_SECURE_COOKIES: bool = config("SECURE_COOKIES", cast=bool, default=True)
    AUTH_SAME_SITE: str = config("SAME_SITE", cast=str, default="strict")

    ALLOW_SMS_AUTH: bool = config("ALLOW_SMS_AUTH", default=False, cast=bool)
    USER_SERVICE_PHONE_NUMBER_URL: str = config(
        "USER_SERVICE_PHONE_NUMBER_URL", cast=str, default="0"
    )

    DEBUG_MODE: bool = config("DEBUG_MODE", cast=bool, default=False)

    # DATABASE CONFIG
    DB_HOST: str = config("DB_HOST")
    DB_PORT: int = config("DB_PORT", cast=int)
    DB_USER: str = config("DB_USER")
    DB_PASSWORD: str = config("DB_PASSWORD")
    DB_NAME: str = config("DB_NAME")
    DB_TYPE: str = config("DB_TYPE")
    DB_URL: str = config("DB_URL", default="0", cast=str)

    # SMTP CONFIG
    SMTP_SERVER: str = config("SMTP_SERVER", cast=str, default="smtp.gmail.com")
    SMTP_PORT: int = config("SMTP_PORT", cast=int, default=587)
    EMAIL_ADDRESS: str = config("EMAIL_ADDRESS")
    EMAIL_PASSWORD: str = config("EMAIL_PASSWORD")

    MJML_TEMPLATE_DIR: str = config(
        "MJML_TEMPLATE_DIR",
        cast=str,
        default=f"/home/ajiboye/Authentication-System/smtp/templates/html_mail_templates",  # points to the compiled html templates
    )

    # MAIL GUN CONFIG
    MAILGUN_API_KEY: str = config("MAILGUN_API_KEY", default=None)
    MAILGUN_DOMAIN: str = config("MAILGUN_DOMAIN", default=None)

    # TWILIO SMS CONFIG
    TWILIO_ACCOUNT_SID: str = config("TWILIO_ACCOUNT_SID", default=None)
    TWILIO_AUTH_TOKEN: str = config("TWILIO_AUTH_TOKEN", default=None)
    TWILIO_PHONE_NUMBER: str = config("TWILIO_PHONE_NUMBER", default=None)

    # APP INFO
    APP_NAME: str = config("APP_NAME", default="FASTAPI AUTH SYSTEM")
    APP_URL: str = config("APP_URL", default="fastapi-authsystem.example.com")

    FRONTEND_HOME_URL: str = config("FRONTEND_HOME_URL")
    FRONTEND_DASHBOARD_URL: str = config(
        "FRONTEND_DASHBOARD_URL", cast=str, default=""
    )  # Optional
    FRONTEND_EMAIL_VERIFICATION_URL: str = config(
        "FRONTEND_EMAIL_VERIFICATION_URL",
        default=f"{FRONTEND_HOME_URL.strip('/')}/auth/verify-email",
    )
    FRONTEND_MAGIC_LINK_VERIFICATION_URL: str = config(
        "FRONTEND_MAGIC_LINK_VERIFICATION_URL",
        default=f"{FRONTEND_HOME_URL.strip('/')}/auth/magic-link/verify",
    )
    FRONTEND_PASSWORD_RESET_URL: str = config(
        "FRONTEND_PASSWORD_RESET_URL",
        default=f"{FRONTEND_HOME_URL.strip('/')}/reset-password",
    )

    ENCRYPTER_SECRET_KEY: str = config(
        "ENCRYPTER_SECRET_KEY",
        cast=str,
        # generated using Fernet.generate_key()
        default="Krq0Q8LWlYYv7famIjZ1k2gyzRZqEnKUqeEz2JX9CaQ=",
    )

    # OAUTH CONFIG
    GITHUB_CLIENT_ID: str = config("GITHUB_CLIENT_ID")
    GITHUB_CLIENT_SECRET: str = config("GITHUB_CLIENT_SECRET", default="acde12")

    GOOGLE_CLIENT_ID: str = config("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET: str = config("GOOGLE_CLIENT_SECRET")

    FACEBOOK_APP_ID: str = config("FACEBOOK_APP_ID", default="acde12")
    FACEBOOK_APP_SECRET: str = config("FACEBOOK_APP_SECRET", default="acde12")

    # MAXMIND CREDENTIALS (FOR GEOLOCATION)
    MAXMIND_ACCOUNT_ID: str = config("MAXMIND_ACCOUNT_ID")
    MAXMIND_LICENSE_KEY: str = config("MAXMIND_LICENSE_KEY")

    MAXMIND_MMDB_DATABASE_PATH: str = config(
        "MAXMIND_MMDB_DATABASE_PATH",
        cast=str,
        default=f"{BASE_DIR}/geoip/GeoLite2-City.mmdb",
    )

    AUDIT_LOGS_LIFETIME: int = config("AUDIT_LOGS_LIFETIME", cast=int, default=90)


settings = Settings()
