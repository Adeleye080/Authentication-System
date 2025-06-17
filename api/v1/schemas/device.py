from pydantic import BaseModel


class DeviceAgentSchema(BaseModel):
    """Model for device agent utility"""

    ip_address: str
    device_name: str
    user_agent: str
