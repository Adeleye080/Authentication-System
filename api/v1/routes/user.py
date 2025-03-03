from fastapi import APIRouter, status
from api.v1.schemas.user import User


user_router = APIRouter(prefix="/auth")


@user_router.post("/create")
def create_new_auth_user(user: User):
    """
    Registers new user in the auth system
    """
    pass
