from fastapi import APIRouter
from api.v1.routes.user import user_router
from api.v1.routes.auth import auth_router
from api.v1.routes.two_factor_auth import two_factor_auth_router
from api.v1.routes.audit_logs import audit_log_router
from api.v1.routes.oauth2 import oauth2_router  # type: ignore
from api.v1.routes.country_blacklist import country_blacklist_router
from api.v1.routes.device import user_device_router


api_version_one = APIRouter(prefix="/api/v1/auth")

api_version_one.include_router(auth_router)
api_version_one.include_router(oauth_router)
api_version_one.include_router(oauth2_router)
api_version_one.include_router(two_factor_auth_router)
api_version_one.include_router(user_router)
api_version_one.include_router(user_device_router)
api_version_one.include_router(audit_log_router)
api_version_one.include_router(country_blacklist_router)
