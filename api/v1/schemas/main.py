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

class HomeResponse(BaseModel):
    """
    Homepage Response Model
    """

    message: str
    data: Union[Author, Dict[str, str]] = {"author": {}, "URL": "Site Url"}
    status_code: int = 200
