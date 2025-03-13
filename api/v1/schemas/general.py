from pydantic import BaseModel


class ServerError(BaseModel):
    """schema for general error message"""

    message: str = "error message"
    error: str = "the error"
    status_code: int = 500
