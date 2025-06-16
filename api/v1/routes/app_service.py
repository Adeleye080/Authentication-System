from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from api.v1.models.user import User
from api.v1.services import application_service, user_service
from api.v1.schemas.app_service import (
    ServiceAppCreate,
    ActivateServiceRequest,
    DeactivateServiceRequest,
    ServiceAuthRequest,
)
from api.utils.json_response import JsonResponseDict
from db.database import get_db


app_router = APIRouter(prefix="/services", tags=["App Services"])


@app_router.get(
    "/get", summary="fetch all app services", status_code=status.HTTP_200_OK
)
async def get_all_apps(
    superadmin: User = Depends(user_service.get_current_superadmin),
    db: Session = Depends(get_db),
):
    """Retrieve all registered app services"""

    apps = application_service.fetch_all(db=db)

    data = [app.to_dict() for app in apps]

    # audit log

    return JsonResponseDict(
        message="Retrieved registered apps", data=data, status_code=status.HTTP_200_OK
    )


@app_router.post(
    "/new", status_code=status.HTTP_201_CREATED, summary="create new app service"
)
async def create_app_service(
    data: ServiceAppCreate,
    superadmin: User = Depends(user_service.get_current_superadmin),
    db: Session = Depends(get_db),
):
    """Create a new service app"""

    app_secret, app = application_service.create_app(
        db=db, service_name=data.name, description=data.description
    )

    data = app.to_dict()
    data["secret"] = app_secret

    # audit log

    return JsonResponseDict(
        message="A new service app has been successfully created. The app secret will only be shown once. Store it securely. You will not be able to view it again.",
        status_code=status.HTTP_200_OK,
        data=data,
    )


@app_router.post("/activate")
async def activate_service(
    data: ActivateServiceRequest,
    db: Session = Depends(get_db),
    superadmin: User = Depends(user_service.get_current_superadmin),
):
    """Activate an app service"""

    application_service.activate(service_id=data.service_id, db=db)

    return JsonResponseDict(
        message="Cheers, app has been activated", status_code=status.HTTP_200_OK
    )


@app_router.post("/deactivate")
async def deactivate_service(
    data: DeactivateServiceRequest,
    db: Session = Depends(get_db),
    superadmin: User = Depends(user_service.get_current_superadmin),
):
    """Deactivate an app service."""

    application_service.deactivate(service_id=data.service_id, db=db)

    return JsonResponseDict(
        message="App deactivated successfully", status_code=status.HTTP_200_OK
    )


@app_router.post("/authenticate", status_code=status.HTTP_200_OK)
async def authenticate_service(
    data: ServiceAuthRequest,
    db: Session = Depends(get_db),
):
    """Authenticate an app service"""

    app_access_token = application_service.authenticate(
        service_id=data.service_id, service_secret=data.service_secret, db=db
    )

    return JsonResponseDict(
        message="Service app login successfull", data={"app_token": app_access_token}
    )


@app_router.delete(
    "/delete/{service_id}",
    summary="delete an app service",
    status_code=status.HTTP_200_OK,
)
async def delete_a_service(
    service_id: str,
    db: Session = Depends(get_db),
    superadmin: User = Depends(user_service.get_current_superadmin),
):
    """ """

    deleted_app = application_service.delete_app(db=db, service_id=service_id)

    return JsonResponseDict(
        message=f"deleted service app ({deleted_app.name}) successfully",
        status_code=status.HTTP_200_OK,
    )
