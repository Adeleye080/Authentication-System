from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict
from enum import Enum as PyEnum


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


class AuditLogCreate(BaseModel):
    """Request schema for audit log"""

    user_id: str = "related user id"
    event: str
    description: str
    status: str
    ip_address: Optional[str]
    user_agent: Optional[str]
    details: Optional[Dict] = {}


class AuditLogEventEnum(str, PyEnum):
    """All Available Audit Log Events"""

    LOGIN = "USER LOGIN"
    PASSWORD_CHANGE = "PASSWORD CHANGE"
    PASSWORD_RESET = "PASSWORD RESET"
    CREATE_ACCOUNT = "CREATE ACCOUNT"
    REQUEST_VERIFICATION = "REQUEST_VERIFICATION"
    UPDATE_ACCOUNT = "UPDATE ACCOUNT"
    REQUEST_MAGIC_LINK = "REQUEST MAGIC LINK"
    MAIL_ERROR = "ERROR PROCESSING/SENDING MAIL"
    DELETE_USER = "DELETED A USER"
    DELETE_SELF = "SOFT-DELETE SELF ACCOUNT"
    HARD_DELETE = "HARD DELETE A USER"
    VERIFY_EMAIL = "USER VERIFIED THEIR EMAIL"


class AuditLogStatuses(str, PyEnum):
    """Log statuses"""

    FAILED = "FAILED"
    SUCCESS = "SUCCESS"
    IN_BETWEEN = "SUCCESS BUT ERROR OCCURRED"
