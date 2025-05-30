from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from fastapi.responses import RedirectResponse
from authlib.integrations.starlette_client import OAuth  # type: ignore
from starlette.requests import Request
import logging
from api.utils.settings import settings
from api.v1.services import (
    oauth2_service,
    user_service,
    audit_log_service,
    notification_service,
)
from api.v1.models.user import User
from api.v1.schemas.audit_logs import (
    AuditLogCreate,
    AuditLogEventEnum,
    AuditLogStatuses,
)
from api.v1.schemas.user import LoginSource
from sqlalchemy.orm import Session
from db.database import get_db
import random
import datetime as dt


logger = logging.getLogger(__name__)


oauth2_router = APIRouter(prefix="/oauth2", tags=["OAuth2"])


@oauth2_router.post("/login/{provider}")
async def login(request: Request, provider: str):
    """Login route for OAuth2 providers"""

    if provider not in oauth2_service.secureOAuth()._registry:
        raise HTTPException(status_code=400, detail="Unsupported provider")

    # Redirect to the provider's authorization URL
    if provider == "github":
        redirect_uri = request.url_for("authorize", provider="github")
        return await oauth2_service.secureOAuth().github.authorize_redirect(
            request, redirect_uri
        )
    elif provider == "facebook":
        redirect_uri = request.url_for("authorize", provider="facebook")
        return await oauth2_service.secureOAuth().facebook.authorize_redirect(
            request, redirect_uri
        )
    elif provider == "google":
        redirect_uri = request.url_for("authorize", provider="google")
        return await oauth2_service.secureOAuth().google.authorize_redirect(
            request, redirect_uri
        )


@oauth2_router.get("/authorize/{provider}", include_in_schema=False)
async def authorize(
    provider: str, request: Request, bgt: BackgroundTasks, db: Session = Depends(get_db)
):
    """Authorization callback route for OAuth2 providers"""

    if provider not in oauth2_service.secureOAuth()._registry:
        raise HTTPException(status_code=400, detail="Unsupported provider")

    if provider == "github":
        token = await oauth2_service.secureOAuth().github.authorize_access_token(
            request
        )
        user_info = await oauth2_service.secureOAuth().github.get("user", token=token)
    elif provider == "google":
        token = await oauth2_service.secureOAuth().google.authorize_access_token(
            request
        )
        user_info = await oauth2_service.secureOAuth().google.get(
            "userinfo", token=token
        )
    elif provider == "facebook":
        token = await oauth2_service.secureOAuth().facebook.authorize_access_token(
            request
        )
        user_info = await oauth2_service.secureOAuth().facebook.get(
            "me?fields=id,name,email,first_name,middle_name,last_name,birthday,gender,picture",
            token=token,
        )
    else:
        raise HTTPException(status_code=400, detail="Unsupported provider")

    user_email = user_info.get("email", None)

    if not user_email:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Invalid user object from OAuth provider",
        )

    # generate user access and refresh tokens
    user_exist, user_obj = User().user_exists(db=db, email=user_email)

    if not user_exist:
        user = User(email=user_email, password=str(random.randint(5, 15)))
        user.is_active = True
        user.is_verified = True
        user.save(db=db)
        # send welcome email to user
        notification_service.send_welcome_mail(user=user, bgt=bgt)

        # send new user info to webhook url in the background
        oauth2_service.post_oauth_signup_webhook(bgt, user_info)
    else:
        user = user_obj

    user_access_token = user_service.create_access_token(db=db, user_obj=user)
    user_refresh_token = user_service.create_refresh_token(db=db, user_id=user.id)
    user.last_login = dt.datetime.now(dt.timezone.utc)

    if provider == "github":
        user.login_source = LoginSource.GITHUB
    elif provider == "facebook":
        user.login_source = LoginSource.FACEBOOK
    elif provider == "google":
        user.login_source = LoginSource.GOOGLE

    # update login source and last login time
    user.save(db=db)

    # construct redirect url
    # add access and refresh tokens to the redirect uri if cookies are not allowed
    # otherwise, set them in the cookies
    redirect_uri = (
        f"{settings.FRONTEND_HOME_URL.strip('/')}/auth-callback?auth_success=true"
    )
    if not settings.ALLOW_AUTH_COOKIES:
        redirect_uri += (
            f"&access_token={user_access_token}&refresh_token={user_refresh_token}"
        )

    # redirect to frontend with success message
    response = RedirectResponse(
        url=redirect_uri,
        status_code=status.HTTP_303_SEE_OTHER,
    )

    # set cookies
    if settings.ALLOW_AUTH_COOKIES:
        response.set_cookie(
            key="access_token",
            value=user_access_token,
            httponly=True,
            secure=settings.AUTH_SECURE_COOKIES,
            samesite=settings.AUTH_SAME_SITE,
            expires=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        )

        response.set_cookie(
            key="refresh_token",
            value=user_refresh_token,
            httponly=True,
            secure=settings.AUTH_SECURE_COOKIES,
            samesite=settings.AUTH_SAME_SITE,
            expires=settings.JWT_REFRESH_EXPIRY,
        )

    # audit log
    audit_log_service.log(
        db=db,
        background_task=bgt,
        schema=AuditLogCreate(
            user_id=user.id,
            event=AuditLogEventEnum.LOGIN,
            status=AuditLogStatuses.SUCCESS,
            ip_address="Not Available",
            details={
                "provider": provider,
                "user_info": user_info,
            },
            user_agent="Not Available",
            description=f"OAuth Login: User {user.email} logged in using {provider}",
        ),
    )

    return response
