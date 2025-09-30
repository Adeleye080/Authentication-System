from fastapi import APIRouter, Depends, status, BackgroundTasks, HTTPException, Path
from sqlalchemy.orm import Session
from db.database import get_db
from api.v1.models.attributes import UserAttribute
from api.v1.schemas.attributes import UserAttributeCreate, AttributeAssignmentRequest
from api.v1.models.user import User
from api.v1.services import (
    user_service,
    audit_log_service,
    notification_service,
    attribute_service,
)
from api.utils.json_response import JsonResponseDict

# from api.v1.schemas.attributes import UserAttributeCreate, UserAttributeResponse


user_attrs_router = APIRouter(prefix="/attributes", tags=["User Attributes"])


@user_attrs_router.post(
    "/new",
    # response_model=UserAttribute,
    status_code=status.HTTP_201_CREATED,
)
async def create_new_attribute(
    data: UserAttributeCreate,
    db: Session = Depends(get_db),
    admin_user: User = Depends(user_service.get_current_user),
):
    """create a new attribute."""

    user_service.ensure_superadmin(admin_user)

    await attribute_service.create_new(db=db, schema=data)

    return JsonResponseDict(message="Attribute has been created")


@user_attrs_router.post("/assign/{user_id}")
async def assign_attribute_to_user(
    user_id: str,
    data: AttributeAssignmentRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(user_service.get_current_user),
):
    """Assign attributes to a user"""

    user_service.ensure_administrator(admin)

    # user_obj = user_service.fetch_by_id(db=db, id=user_id)

    await attribute_service.assign_attributes_to_user(
        db=db, user_id=user_id, attrs_ass=data.assignments, assigner=admin
    )

    # Log this action in the audit logs

    return JsonResponseDict(message="Attributes have been assigned to the user")


@user_attrs_router.get(
    "/@me",
    status_code=status.HTTP_200_OK,
    summary="Get self attributes",
)
async def get_self_attributes(
    user: User = Depends(user_service.get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve self attributes"""

    attributes = user_service.get_user_attributes(db=db, user_obj=user)

    if attributes is None or len(attributes) == 0:
        return JsonResponseDict(
            message="you have no attributes",
            data="empty",
            status_code=status.HTTP_200_OK,
        )

    return JsonResponseDict(
        message="successfully retrieved your attributes", data=attributes
    )


@user_attrs_router.get(
    "/user/{user_id}",
    status_code=status.HTTP_200_OK,
)
async def get_user_attributes(
    user_id: str = Path(..., description="The ID of the user"),
    db: Session = Depends(get_db),
    admin_user: User = Depends(user_service.get_current_user),
):
    """Retrieve the attributes of a user"""

    user_service.ensure_administrator(admin_user)

    attributes = user_service.get_user_attributes(db=db, user_id=user_id)

    return JsonResponseDict(
        message="successfully retrieved user attributes",
        data=attributes if attributes else "empty",
    )


@user_attrs_router.delete(
    "/{attribute_id}/user/{user_id}",
    status_code=status.HTTP_200_OK,
)
async def delete_user_attribute(
    user_id: str = Path(..., description="The ID of the user"),
    attribute_id: int = Path(
        ..., description="ID of the name of the attribute to delete"
    ),
    db: Session = Depends(get_db),
    admin_user: User = Depends(user_service.get_current_user),
):
    """Delete a specific attribute from a user"""

    user_service.ensure_administrator(admin_user)

    user_service.delete_user_attribute(
        db=db, user_id=user_id, attribute_id=attribute_id
    )

    return JsonResponseDict(message="Attribute has been deleted successfully")
