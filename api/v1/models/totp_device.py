from api.v1.models.base_model import BaseModel
from sqlalchemy import Column, String, ForeignKey, Boolean, LargeBinary, DateTime


class TOTPDevice(BaseModel):
    """
    Database model representing a TOTP device for two-factor authentication.

    This model stores the secret key used for generating TOTP codes, along with the confirmation status and the relationship to the user who owns the device.
    """

    __tablename__ = "auth_totp_devices"

    user_id = Column(
        String(36),
        ForeignKey("auth_users.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )
    secret = Column(LargeBinary, nullable=False)
    confirmed = Column(Boolean, default=False, index=True)
    last_used = Column(DateTime, nullable=True, index=True)

    # add table indexes
    __table_args__ = ({"extend_existing": True},)

    def __str__(self):
        if self.user:
            return f"{self.user.email}'s TOTP device"
        return f"TOTP device for user_id: {self.user_id}"
