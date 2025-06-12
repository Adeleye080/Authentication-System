from fastapi import APIRouter, HTTPException, status, Depends
from api.v1.models.user import User
from api.v1.services import user_service
from api.v1.schemas.user import UserID
from db.database import get_db
from sqlalchemy.orm import Session


user_device_router = APIRouter(prefix="/devices", tags=["User Device"])


@user_device_router.get("/@me", status_code=status.HTTP_200_OK)
def get_devices(user: User = Depends(user_service.get_current_user)):
    """
    Retrieve self devices information
    """

    user_devices = user.devices

    devices = [device.to_dict(hide_sensitive_info=True) for device in user_devices]
    return devices


@user_device_router.get(
    "/user/{user_id}",
    tags=["Moderator", "Superadmin"],
    response_model=list,
    status_code=status.HTTP_200_OK,
)
def get_user_devices_by_user_id(
    user_id: str,
    moderator_superadmin: User = Depends(user_service.get_current_user),
    db: Session = Depends(get_db),
):
    """Get all devices belonging to a user"""

    if not any([moderator_superadmin.is_superadmin, moderator_superadmin.is_moderator]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Not enough permissions."
        )

    user_devices = user_service.fetch_by_id(db=db, id=user_id).devices
    user_devices = [
        device.to_dict(hide_sensitive_info=False) for device in user_devices
    ]

    return user_devices
