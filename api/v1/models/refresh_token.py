from sqlalchemy import Column, Boolean, DateTime, ForeignKey, String, Index
from sqlalchemy.orm import relationship
from api.v1.models.base_model import BaseModel


class RefreshToken(BaseModel):
    __tablename__ = "auth_refresh_tokens"

    user_id = Column(
        String(36), ForeignKey("auth_users.id", ondelete="CASCADE"), nullable=False
    )
    token = Column(String(400), unique=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)

    user = relationship("User", back_populates="refresh_tokens")

    __table_args__ = (
        Index("ix_refresh_token_owner", "user_id"),
        Index("ix_refresh_token", "token"),
        Index("ix_refresh_token_is_revoked", "revoked"),
        Index("ix_refresh_token_expire_at", "expires_at"),
    )

    def to_dict(self):
        refresh_token_dict = super().to_dict()
        refresh_token_dict["expires_at"] = self.expires_at.isoformat()
        return refresh_token_dict
