"""Notification Service Module"""

from smtp.mailing import send_mail
from fastapi import BackgroundTasks
from api.v1.models.user import User
from api.utils.settings import settings
from api.utils.twilo_sms import send_sms_message
from api.utils.encrypters_and_decrypters import (
    generate_magic_link_token,
    generate_user_verification_token,
    generate_password_reset_token,
)


class Notification:
    """
    Notification class.

    Handles the notification of users through email and push notification.
    All methods are background tasks
    """

    def send_verify_email_mail(self, user: User, bgt: BackgroundTasks) -> None:
        """send email asking user to verify their email

        params:

        :param user: User Object
        :param bgt: fastapi background task obj

        """

        # logic to generate verification token
        token = generate_user_verification_token(user.email)
        verification_link = (
            f"{settings.FRONTEND_EMAIL_VERIFICATION_URL.strip('/')}?token={token}"
        )

        bgt.add_task(
            func=send_mail,
            recipient=user.email,
            subject="Verify Your Email",
            template_name="verify_email_template.html",
            template_context={
                "username": user.email,
                "verificationLink": verification_link,
            },
        )

    def send_magic_link_mail(self, user: User, bgt: BackgroundTasks) -> None:
        """Send magic link to user to login without entering password"""

        # logic to generate verification token
        token = generate_magic_link_token(user.email)
        magic_link = (
            f"{settings.FRONTEND_MAGIC_LINK_VERIFICATION_URL.strip('/')}?token={token}"
        )

        bgt.add_task(
            func=send_mail,
            recipient=user.email,
            subject="Your Magic Link",
            template_name="magic_link_template.html",
            template_context={
                "username": user.email,
                "magicLink": magic_link,
            },
        )
        print("magic link: ", magic_link)
        return None

    def send_password_reset_mail(self, user: User, bgt: BackgroundTasks) -> None:
        """Send password reset link to user"""

        token = generate_password_reset_token(user.email)
        password_reset_link = (
            f"{settings.FRONTEND_PASSWORD_RESET_URL.strip('/')}?token={token}"
        )

        bgt.add_task(
            func=send_mail,
            recipient=user.email,
            subject="Reset Your Password",
            template_name="password_reset_template.html",
            template_context={
                "username": user.email,
                "resetLink": password_reset_link,
            },
        )

    def send_welcome_mail(self, user: User, bgt: BackgroundTasks) -> None:
        """
        sends "welcome to the platform" mail to user. \n
        use upon successfull user verification or user creation via oauth2
        """

        bgt.add_task(
            func=send_mail,
            recipient=user.email,
            subject="Welcome to the platform",
            template_name="welcome_template.html",
            template_context={
                "username": user.email,
                "dashboardLink": settings.FRONTEND_DASHBOARD_URL.strip("/")
                or settings.FRONTEND_HOME_URL.strip("/"),
            },
        )

    def send_success_password_reset_or_changed_mail(
        self, user: User, bgt: BackgroundTasks
    ) -> None:
        """Notify user of successful password change/reset."""

        bgt.add_task(
            func=send_mail,
            recipient=user.email,
            subject="Your Password has Changed",
            template_name="success_password_reset.html",
            template_context={
                "username": user.email,
                "loginLink": settings.FRONTEND_DASHBOARD_URL.strip("/")
                or settings.FRONTEND_HOME_URL.strip("/"),
            },
        )

    def send_2fa_setup_success_mail(self, user: User, bgt: BackgroundTasks) -> None:
        """
        Send mail to notify user of successful 2FA setup

        :param user: User Object
        :param bgt: fastapi background task obj
        """

        template_context = {
            "dashboardLink": settings.FRONTEND_DASHBOARD_URL.strip("/")
            or settings.FRONTEND_HOME_URL.strip("/"),
            "username": user.email,
        }

        bgt.add_task(
            func=send_mail,
            recipient=user.email,
            subject="Security Update: 2FA Enabled on Your Account",
            template_name="success_2fa_setup.html",
            template_context=template_context,
        )

    def totp_2fa_disabled_mail(self, user: User, bgt: BackgroundTasks) -> None:
        """Inform user that 2FA is disabled"""

        bgt.add_task(
            func=send_mail,
            recipient=user.email,
            subject="Security Alert: 2FA Disabled",
            template_name="disabled_2fa.html",
            template_context={
                "username": user.email,
                "dashboardLink": settings.FRONTEND_DASHBOARD_URL.strip("/")
                or settings.FRONTEND_HOME_URL.strip("/"),
            },
        )

    def send_sms_otp(self, number: str, otp_code: int, bgt: BackgroundTasks) -> None:
        """Send OTP to user via SMS"""

        bgt.add_task(
            func=send_sms_message,
            phone_number=number,
            message=f"Your OTP code is {otp_code}\n\nPlease do not share this code with anyone.",
        )
