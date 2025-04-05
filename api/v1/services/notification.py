"""Notification Service Module"""

from smtp.mailing import send_mail
from fastapi import BackgroundTasks
from api.v1.models.user import User
from api.utils.settings import settings
from api.utils.encrypters_and_decrypters import (
    generate_magic_link_token,
    generate_user_verification_token,
)


class Notification:
    """
    Notification class.

    Handles the notification of users through email and push notification.
    All methods are background tasks
    """

    def send_push_notification():
        """ """
        pass

    def send_verify_email_mail(self, user: User, bgt: BackgroundTasks):
        """send email asking user to verify their email

        params:

        :param user: User Object
        :param verification: verification link to send to user
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
                "username": user.username,
                "verificationLink": verification_link,
            },
        )

    def send_magic_link_mail(self, user: User, bgt: BackgroundTasks):
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
                "username": user.username,
                "magicLink": magic_link,
            },
        )

        # should return None
        # return None
        return magic_link
