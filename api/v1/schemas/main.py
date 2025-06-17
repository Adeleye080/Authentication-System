from pydantic import BaseModel
from typing import Dict, Union


class ProbeServerResponse(BaseModel):
    """schema for server probe response"""

    message: str = "Server message"
    status: str = "Server status"

    class Config:
        from_attributes = True


class Author(BaseModel):
    """Site Author"""

    author: Dict[str, str]


class HomeRespData(BaseModel):
    """Data for the Home Response Model"""

    author: dict = {}
    contributors: list = []
    URL: str = "Home URL"
    documentation: str


class HomeResponse(BaseModel):
    """
    Homepage Response Model
    """

    message: str
    data: HomeRespData
    status_code: int = 200
