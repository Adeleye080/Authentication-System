from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from fastapi.responses import RedirectResponse
from starlette.requests import Request
import logging
from api.utils.settings import settings
from api.utils.user_device_agent import get_device_info
from api.v1.services import (
    oauth2_service,
    user_service,
    audit_log_service,
    notification_service,
    devices_service,
)
from api.v1.models.user import User
from api.v1.schemas.audit_logs import (
    AuditLogCreate,
    AuditLogEventEnum,
    AuditLogStatuses,
)
from api.v1.schemas.user import LoginSource
from api.v1.services import geoip_service
from api.utils.json_response import JsonResponseDict
from sqlalchemy.orm import Session
from db.database import get_db
import random
import datetime as dt


logger = logging.getLogger(__name__)


oauth2_router = APIRouter(prefix="/oauth2", tags=["Social Login"])


@oauth2_router.get("/providers")
async def all_available_providers():
    """Retrieve list of available supported OAuth 2.0 Providers"""

    providers = oauth2_service.registered_providers

    return JsonResponseDict(
        message="Successfully fetched supported OAuth providers", data=providers
    )


@oauth2_router.get("/login/{provider}")
async def login(
    request: Request,
    provider: str,
    _: None = Depends(geoip_service.blacklisted_country_dependency_check),
):
    """
    Login route for OAuth2 providers\n
    The `provider` parameter should be lowercase.
    """

    if provider not in oauth2_service.secureOAuth()._registry:
        raise HTTPException(
            status_code=400, detail=f"{provider} OAuth is not supported"
        )

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

    elif provider == "microsoft":
        redirect_uri = request.url_for("authorize", provider="microsoft")
        return await oauth2_service.secureOAuth().microsoft.authorize_redirect(
            request, redirect_uri
        )

    elif provider == "apple":
        redirect_uri = request.url_for("authorize", provider="apple")
        return await oauth2_service.secureOAuth().apple.authorize_redirect(
            request, redirect_uri
        )


@oauth2_router.get("/authorize/{provider}/callback")
async def authorize(
    provider: str, request: Request, bgt: BackgroundTasks, db: Session = Depends(get_db)
):
    """
    Authorization callback route for OAuth2 providers\n
    The `provider` parameter should be all lowercase.
    """

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
    elif provider == "microsoft":
        token = await oauth2_service.secureOAuth().microsoft.authorize_access_token(
            request
        )
        response = await oauth2_service.secureOAuth().microsoft.get("me", token=token)
        user_info = response.json()
        email = user_info.get("mail", user_info.get("userPrincipalName"))
        user_info["email"] = email

    elif provider == "apple":
        token = await oauth2_service.secureOAuth().apple.authorize_access_token(request)
        id_token = token.get("id_token", None)
        if not id_token:
            raise HTTPException(status_code=400, detail="Invalid User Apple ID token")
        user_info = token

    else:
        raise HTTPException(status_code=400, detail="Unsupported provider")

    user_email = user_info.get("email", None)
    user_obj = None
    user_exist = False

    if not user_email:
        if provider == "apple":
            # Apple may not provide email if it's not verified or if the user chose to hide it
            # get user object with apple persistent sub id
            # user_exist = True
            # user_obj =
            pass
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Invalid user object from OAuth provider",
        )

    # generate user access and refresh tokens
    if not user_exist and not user_obj:
        user_exist, user_obj = User().user_exists(db=db, email=user_email)

    if not user_exist:
        user = User(
            email=user_email,
            password=user_service.hash_password(str(random.randint(5, 150))),
        )
        user.is_active = True
        user.is_verified = True
        user.save(db=db)
        # send welcome email to user
        notification_service.send_welcome_mail(user=user, bgt=bgt)

        # audit log
        audit_log_service.log(
            db=db,
            background_task=bgt,
            schema=AuditLogCreate(
                user_id=user.id,
                event=AuditLogEventEnum.CREATE_ACCOUNT,
                status=AuditLogStatuses.SUCCESS,
                ip_address="Not Available",
                details={
                    "provider": provider,
                    "user_info": user_info,
                },
                user_agent="Not Available",
                description=f"Account creation: created account for {user.email} via {provider} OAuth",
            ),
        )

        # send new user info to webhook url in the background
        oauth2_service.post_oauth_signup_webhook(bgt, user_info)
    else:
        user = user_obj

    user_access_token = user_service.create_access_token(db=db, user_obj=user)
    user_refresh_token = user_service.create_refresh_token(
        db=db, user_id=user.id, by_oauth=True
    )
    user.last_login = dt.datetime.now(dt.timezone.utc)

    if provider == "github":
        user.login_source = LoginSource.GITHUB
    elif provider == "facebook":
        user.login_source = LoginSource.FACEBOOK
    elif provider == "google":
        user.login_source = LoginSource.GOOGLE
    elif provider == "apple":
        user.login_source = LoginSource.APPLE
    elif provider == "microsoft":
        user.login_source = LoginSource.MICROSOFT

    # update login source and last login time
    user.save(db=db)

    # save user device
    device_info = await get_device_info(request)
    devices_service.create_with_bgt(db=db, device_info=device_info, owner=user, bgt=bgt)

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
        JWT_REFRESH_EXPIRY_SECONDS = int(
            dt.timedelta(days=settings.JWT_REFRESH_EXPIRY_DAYS).total_seconds()
        )
        response.set_cookie(
            key="refresh_token",
            value=user_refresh_token,
            httponly=True,
            secure=settings.AUTH_SECURE_COOKIES,
            samesite=settings.AUTH_COOKIE_SAME_SITE,
            path=request.url_for("refresh").path,
            expires=JWT_REFRESH_EXPIRY_SECONDS,
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
