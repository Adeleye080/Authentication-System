from pydantic import BaseModel
from typing import Dict


class ProbeServerResponse(BaseModel):
    """schema for server probe response"""

    message: str = "Server message"
    status: str = "Server status"

    class Config:
        from_attributes = True


class HomeResponse(BaseModel):
    """
    Homepage Response Model
    """

    message: str
    data: Dict
    status_code: int = 200
