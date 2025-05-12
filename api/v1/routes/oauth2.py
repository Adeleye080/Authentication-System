from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from authlib.integrations.starlette_client import OAuth  # type: ignore
from starlette.requests import Request
from starlette.config import Config
from api.utils.settings import settings
import jwt
import datetime
import logging
from api.utils.json_response import JsonResponseDict
from api.v1.services import oauth2_service

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
oauth2_router = APIRouter(prefix="/oauth2", tags=["OAuth2"])

# OAuth configurations
config = Config(environ={})
oauth = OAuth(config)

oauth.register(
    name="github",
    client_id=settings.GITHUB_CLIENT_ID,
    client_secret=settings.GITHUB_CLIENT_SECRET,
    access_token_url="https://github.com/login/oauth/access_token",
    authorize_url="https://github.com/login/oauth/authorize",
    api_base_url="https://api.github.com/",
    client_kwargs={"scope": "user:email"},
)

oauth.register(
    name="google",
    client_id=settings.GOOGLE_CLIENT_ID,
    client_secret=settings.GOOGLE_CLIENT_SECRET,
    access_token_url="https://oauth2.googleapis.com/token",
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    api_base_url="https://www.googleapis.com/oauth2/v1/",
    client_kwargs={"scope": "openid email profile"},
)

oauth.register(
    name="facebook",
    client_id=settings.FACEBOOK_CLIENT_ID,
    client_secret=settings.FACEBOOK_CLIENT_SECRET,
    access_token_url="https://graph.facebook.com/oauth/access_token",
    authorize_url="https://www.facebook.com/dialog/oauth",
    api_base_url="https://graph.facebook.com/",
    client_kwargs={"scope": "email"},
)


@oauth2_router.get("/login/{provider}")
async def login(request: Request, provider: str):
    """Login route for OAuth2 providers"""

    if provider not in oauth._registry:
        raise HTTPException(status_code=400, detail="Unsupported provider")

    # Redirect to the provider's authorization URL
    if provider == "github":
        redirect_uri = request.url_for("authorize", provider="github")
        return await oauth.github.authorize_redirect(request, redirect_uri)
    elif provider == "facebook":
        redirect_uri = request.url_for("authorize", provider="facebook")
        return await oauth.facebook.authorize_redirect(request, redirect_uri)
    elif provider == "google":
        redirect_uri = request.url_for("authorize", provider="google")
        return await oauth.google.authorize_redirect(request, redirect_uri)


@oauth2_router.get("/authorize/{provider}", include_in_schema=False)
async def authorize(provider: str, request: Request):
    """Authorization callback route for OAuth2 providers"""

    if provider not in oauth._registry:
        raise HTTPException(status_code=400, detail="Unsupported provider")

    token = await oauth.google.authorize_access_token(request)
    if provider == "github":
        user_info = await oauth.github.get("user", token=token)
    elif provider == "google":
        user_info = await oauth.google.get("userinfo", token=token)
    elif provider == "facebook":
        user_info = await oauth.facebook.get("me?fields=id,name,email", token=token)
    else:
        raise HTTPException(status_code=400, detail="Unsupported provider")

    user_info = user_info.json()
    print("\n\n", user_info, "\n\n")
    jwt_token = {"token": "some-secure-token"}
    return JSONResponse(content={"token": jwt_token, "user_info": user_info})
