from fastapi import APIRouter
from api.v1.routes.user import user_router
from api.v1.routes.admin_and_moderator_on_user import admin_and_moderator_on_user_router
from api.v1.routes.admin_on_user import admin_on_user_router
from api.v1.routes.auth import auth_router


api_version_one = APIRouter(prefix="/api/v1/auth")

api_version_one.include_router(auth_router)
api_version_one.include_router(user_router)
api_version_one.include_router(admin_and_moderator_on_user_router)
api_version_one.include_router(admin_on_user_router)
