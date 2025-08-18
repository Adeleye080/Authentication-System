from fastapi import APIRouter, Depends, status, BackgroundTasks, HTTPException, Path
from sqlalchemy.orm import Session
from db.database import get_db
from api.v1.models.attributes import UserAttribute
from api.v1.schemas.attributes import UserAttributeCreate
from api.v1.models.user import User
from api.v1.services import user_service, audit_log_service, notification_service
from api.utils.json_response import JsonResponseDict

# from api.v1.schemas.attributes import UserAttributeCreate, UserAttributeResponse


user_attrs_router = APIRouter(prefix="/attributes", tags=["User Attributes"])


@user_attrs_router.post(
    "/{user_id}",
    # response_model=UserAttribute,
    status_code=status.HTTP_201_CREATED,
)
def create_user_attribute(
    data: UserAttributeCreate,
    db: Session = Depends(get_db),
    user_id: str = Path(..., description="The ID of the user"),
    admin_user: User = Depends(user_service.get_current_user),
):
    """Add new attribute to a user"""

    if not any([admin_user.is_superadmin, admin_user.is_moderator]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Not enough permissions."
        )

    attribute = UserAttribute(user_id=user_id, key=data.key, value=data.value)

    user_service.add_new_attribute_to_user(
        db=db, user_id=user_id, key=data.key, value=data.value
    )

    return JsonResponseDict(message="Attribute has been added to user")


@user_attrs_router.get(
    "/@me",
    status_code=status.HTTP_200_OK,
    summary="Get self attributes",
)
def get_self_attributes(
    user: User = Depends(user_service.get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve self attributes"""

    attributes = user_service.get_user_attributes(db=db, user_obj=user)

    return JsonResponseDict(
        message="successfully retrieved your attributes", data=attributes
    )


@user_attrs_router.get(
    "/{user_id}",
    status_code=status.HTTP_200_OK,
)
def get_user_attributes(
    user_id: str = Path(..., description="The ID of the user"),
    db: Session = Depends(get_db),
    admin_user: User = Depends(user_service.get_current_user),
):
    """Retrieve the attributes of a user"""

    if not any([admin_user.is_superadmin, admin_user.is_moderator]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Not enough permissions."
        )

    attributes = user_service.get_user_attributes(db=db, user_id=user_id)

    return JsonResponseDict(
        message="successfully retrieved user attributes", data=attributes
    )


@user_attrs_router.delete(
    "/{user_id}/{attribute_key}",
    status_code=status.HTTP_200_OK,
)
def delete_user_attribute(
    user_id: str = Path(..., description="The ID of the user"),
    attribute_key: str = Path(
        ..., description="The key/name of the attribute to delete"
    ),
    db: Session = Depends(get_db),
    admin_user: User = Depends(user_service.get_current_user),
):
    """Delete a specific attribute from a user"""

    if not any([admin_user.is_superadmin, admin_user.is_moderator]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Not enough permissions."
        )

    user_service.delete_user_attribute(db=db, user_id=user_id, key=attribute_key)

    return JsonResponseDict(message="Attribute has been deleted successfully")
