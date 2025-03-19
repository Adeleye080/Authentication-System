from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class AuditLogSchema(BaseModel):
    """schema for audit logs"""

    id: str = Field(..., description="Audit Log ID")
    user_id: str = Field(..., description="ID of the User who triggered the event")
    event: str = Field(
        ..., max_length=50, description="Type of event (e.g LOGIN, PASSWORD_RESET)"
    )
    description: str = Field(..., description="Detailed description of the event")
    status: str = Field(..., description="Status of the event (e.g SUCCESS, FAILED)")
    details: Optional[Dict[str, Any]] = Field(
        None, description="Additional event data in JSON format"
    )
    ip_address: Optional[str] = Field(None, description="IP Address of the user")
    user_agent: Optional[str] = Field(
        None, description="User's device or browser information"
    )

    model_config = ConfigDict(from_attributes=True)
