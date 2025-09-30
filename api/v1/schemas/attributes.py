from pydantic import BaseModel, Field
from typing import Optional, List, Tuple


class UserAttributeCreate(BaseModel):
    name: str = Field(
        ...,
        description="The key of the user attribute",
        examples=["department", "clearance_level"],
    )
    allowed_values: Optional[List[str]] = ["IT", "HR", "Finance", "Engineering", "..."]


class UserAttributeResponse(BaseModel):
    id: str
    user_id: str


class AttributeAssignmentRequest(BaseModel):
    assignments: List[Tuple[int, int]] = [(2, 4)]
