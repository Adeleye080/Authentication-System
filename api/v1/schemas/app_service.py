from pydantic import BaseModel, Field
from typing import Optional


class ServiceAppCreate(BaseModel):
    name: str = Field(..., example="payment-service")
    description: Optional[str] = Field(None, example="Handles payment operations")


class ActivateServiceRequest(BaseModel):
    """ """

    service_id: str = Field(..., description="ID of service to activate")


class DeactivateServiceRequest(BaseModel):
    """ """

    service_id: str = Field(..., description="ID of service to deactivate")


class ServiceAuthRequest(BaseModel):
    """ """

    service_id: str = Field(..., description="ID of service to deactivate")
    service_secret: str = Field(..., description="Service secret/password")
