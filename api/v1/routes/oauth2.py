from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from authlib.integrations.starlette_client import OAuth  # type: ignore
from starlette.requests import Request
from starlette.config import Config
from api.utils.settings import settings
import jwt
import datetime
import logging

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


def generate_jwt_token(user_info):
    payload = {
        "user": user_info,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
    return token


@oauth2_router.get("/login/google")
async def login(request: Request):
    redirect_uri = request.url_for("authorize", provider="google")
    print(dir(oauth))
    print(oauth._clients)
    print(type(oauth._clients))
    return await oauth.google.authorize_redirect(request, redirect_uri)


@oauth2_router.get("/authorize/{provider}")
async def authorize(provider: str, request: Request):
    if provider not in oauth._registry:
        raise HTTPException(status_code=400, detail="Unsupported provider")

    # token = await oauth._clients.get(provider).authorize_access_token(request)
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
    jwt_token = generate_jwt_token(user_info)
    return JSONResponse(content={"token": jwt_token, "user_info": user_info})


# @oauth2_router.get("/login")
# async def login(request: Request):
#     redirect_uri = request.url_for("auth", _external=True)
#     return await oauth.google.authorize_redirect(request, redirect_uri)


# @oauth2_router.get("/auth")
# async def auth(request: Request):
#     token = await oauth.google.authorize_access_token(request)
#     user = await oauth.google.parse_id_token(request, token)
#     return {"user_info": user}
