"""
OAuth2 service to handle multiple providers using Authlib.
"""

from fastapi import BackgroundTasks
from authlib.integrations.starlette_client import OAuth
from starlette.config import Config
from api.utils.settings import settings
import logging
import requests


logger = logging.getLogger(__name__)


class OAuth2Service:
    def __init__(self):

        # OAuth configurations
        config = Config(environ={})
        self.oauth = OAuth(config)
        self.registered_providers = []

        if settings.ENABLE_GITHUB_OAUTH:
            # register github
            self.oauth.register(
                name="github",
                client_id=settings.GITHUB_CLIENT_ID,
                client_secret=settings.GITHUB_CLIENT_SECRET,
                access_token_url="https://github.com/login/oauth/access_token",
                authorize_url="https://github.com/login/oauth/authorize",
                api_base_url="https://api.github.com/",
                client_kwargs={"scope": "user:email"},
            )
            self.registered_providers.append("GitHub")

        if settings.ENABLE_GOOGLE_OAUTH:
            # register google
            self.oauth.register(
                name="google",
                client_id=settings.GOOGLE_CLIENT_ID,
                client_secret=settings.GOOGLE_CLIENT_SECRET,
                access_token_url="https://oauth2.googleapis.com/token",
                authorize_url="https://accounts.google.com/o/oauth2/auth",
                server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
                api_base_url="https://www.googleapis.com/oauth2/v1/",
                client_kwargs={"scope": "openid profile email"},
            )
            self.registered_providers.append("Google")

        if settings.ENABLE_FACEBOOK_OAUTH:
            # register facebook
            self.oauth.register(
                name="facebook",
                client_id=settings.FACEBOOK_APP_ID,
                client_secret=settings.FACEBOOK_APP_SECRET,
                access_token_url="https://graph.facebook.com/oauth/access_token",
                authorize_url="https://www.facebook.com/v19.0/dialog/oauth",
                api_base_url="https://graph.facebook.com/v19.0",
                client_kwargs={
                    "scope": "email,user_birthday,user_gender,public_profile"
                },
            )
            self.registered_providers.append("Facebook")

        if settings.ENABLE_MICROSOFT_OAUTH:
            # register microsoft
            self.oauth.register(
                name="microsoft",
                client_id=settings.MICROSOFT_CLIENT_ID,
                client_secret=settings.MICROSOFT_CLIENT_SECRET,
                access_token_url="https://login.microsoftonline.com/common/oauth2/v2.0/token",
                authorize_url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                api_base_url="https://graph.microsoft.com/v1.0/",
                client_kwargs={"scope": "User.Read"},
            )
            self.registered_providers.append("Microsoft")

        if settings.ENABLE_APPLE_OAUTH:
            # register apple
            self.oauth.register(
                name="apple",
                client_id=settings.APPLE_CLIENT_ID,
                client_secret=settings.APPLE_CLIENT_SECRET,
                access_token_url="https://appleid.apple.com/auth/token",
                authorize_url="https://appleid.apple.com/auth/authorize",
                api_base_url="https://appleid.apple.com",
                client_kwargs={"scope": "name email"},
            )
            self.registered_providers.append("Apple")

    def secureOAuth(self) -> OAuth:
        """
        Return the OAuth object with all registered providers.
        """

        return self.oauth

    def _send_webhook(self, webhook_url: str, data):
        """Send a webhook event to the specified URL."""
        try:
            response = requests.post(webhook_url, json=data)
            response.raise_for_status()
        except Exception as e:
            logger.error(f"Webhook failed: {str(e)}")

    def post_oauth_signup_webhook(self, bgt: BackgroundTasks, user_data: dict) -> None:
        """
        Send (POST) `oauth2-signup` event with relevant data to the webhook url
        """

        extracted_info = user_data
        data = {"event": "oauth2-signup"}
        data.update(extracted_info)

        # get webhook url from database
        webhook_url = settings.WEBHOOK_URL
        if not webhook_url:
            return

        bgt.add_task(self._send_webhook, webhook_url, data)

        # log the webhook event
        logger.info(f"New user via OAuth2 webhook sent to {webhook_url}")
