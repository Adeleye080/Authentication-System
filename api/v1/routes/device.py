from fastapi import APIRouter, HTTPException, status, Depends
from api.v1.models.user import User
from api.v1.services import user_service
from api.v1.schemas.user import UserID


user_device_router = APIRouter(prefix="/devices", tags=["User Device"])


@user_device_router.get("/@me", response_model=dict, status_code=status.HTTP_200_OK)
def get_devices(user: User = Depends(user_service.get_current_user)):
    """ """
    pass


@user_device_router.get(
    "/user/{user_id}",
    tags=["Moderator", "Superadmin"],
    response_model=dict,
    status_code=status.HTTP_200_OK,
)
def get_user_devices_by_user_id(
    user_id: str, moderator_superadmin: User = Depends(user_service.get_current_user)
):
    """ """

    if not any([moderator_superadmin.is_superadmin, moderator_superadmin.is_moderator]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Not enough permissions."
        )
    pass
