from fastapi import APIRouter
from api.v1.routes.user import user_router

api_version_one = APIRouter(prefix="/api/v1")

api_version_one.include_router(user_router)
