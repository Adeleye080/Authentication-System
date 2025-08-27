from pydantic import BaseModel, Field


class UserAttributeCreate(BaseModel):
    key: str = Field(
        ..., description="The key of the user attribute", examples=["department"]
    )
    value: str = Field(
        ..., description="The value of the user attribute", examples=["Engineering"]
    )


class UserAttributeResponse(BaseModel):
    id: str
    user_id: str
