""" """

from fastapi import APIRouter, Depends, BackgroundTasks
from fastapi.responses import JSONResponse
from authlib.integrations.starlette_client import OAuth  # type: ignore
from starlette.requests import Request
from starlette.config import Config
from api.utils.settings import settings
import logging
import requests
from api.utils.json_response import JsonResponseDict


logger = logging.getLogger(__name__)


class OAuth2Service:
    def __init__(self):

        # OAuth configurations
        config = Config(environ={})
        self.oauth = OAuth(config)

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

        # register facebook
        self.oauth.register(
            name="facebook",
            client_id=settings.FACEBOOK_APP_ID,
            client_secret=settings.FACEBOOK_APP_SECRET,
            access_token_url="https://graph.facebook.com/oauth/access_token",
            authorize_url="https://www.facebook.com/v19.0/dialog/oauth",
            api_base_url="https://graph.facebook.com/v19.0",
            client_kwargs={"scope": "email,user_birthday,user_gender,public_profile"},
        )

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

    def post_oauth_signup_webhook(self, bgt: BackgroundTasks, user_data: dict):
        """
        Send (POST) `oauth2-signup` event with relevant data to the webhook url
        """

        extracted_info = user_data.get()
        data = {"event": "oauth2-signup"}
        data.update(extracted_info)

        # get webhook url from database
        webhook_url = settings.WEBHOOK_URL

        bgt.add_task(self._send_webhook, webhook_url, data)

        # log the webhook event
        logger.info(f"New user via OAuth2 webhook sent to {webhook_url}")
