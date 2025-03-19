# user/bin/python3
"""User' Device"""

from sqlalchemy import ForeignKey, Column, String, DateTime, func
from api.v1.models.base_model import BaseModel


class Device(BaseModel):
    __tablename__ = "user_devices"

    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    device_name = Column(String(60), index=True)
    ip_address = Column(String(30), nullable=False, index=True)
    user_agent = Column(String(128))
    last_used = Column(
        DateTime(timezone=True), default=func.now(), nullable=False, index=True
    )

    def __repr__(self):
        return f"<UserDevice(id={self.id}, user_id={self.user_id}, device_name={self.device_name})>"
