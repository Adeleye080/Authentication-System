# user/bin/python3
"""User' Device"""

from sqlalchemy import (
    ForeignKey,
    Column,
    String,
    DateTime,
    func,
    UniqueConstraint,
    Boolean,
)
from api.v1.models.base_model import BaseModel


class Device(BaseModel):
    __tablename__ = "auth_user_devices"

    user_id = Column(
        String(36),
        ForeignKey("auth_users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    device_name = Column(String(60), index=True)
    user_agent_string = Column(String(500), nullable=False, index=True)
    last_used = Column(
        DateTime(timezone=True), default=func.now(), nullable=False, index=True
    )

    os_name = Column(String(50), index=True)
    os_version = Column(String(50), index=True)

    is_mobile = Column(Boolean, default=False, nullable=False)
    is_tablet = Column(Boolean, default=False, nullable=False)
    is_pc = Column(Boolean, default=False, nullable=False)
    is_bot = Column(Boolean, default=False, nullable=False)

    device_fingerprint = Column(String(64), nullable=False, index=True)

    __table_args__ = (
        UniqueConstraint(
            "user_id", "device_fingerprint", name="unique_user_device_fingerprint"
        ),
        {"extend_existing": True},
    )

    def __repr__(self):
        return f"<UserDevice(id={self.id}, user_id={self.user_id}, device_name={self.device_name})>"

    def to_dict(self, hide_user_agent_string: bool = True) -> dict:
        """returns a dictionary representation of the instance"""
        info = super().to_dict()
        info["last_used"] = self.last_used.isoformat() if self.last_used else None
        if hide_user_agent_string:
            info.pop("user_agent_string")

        return info
