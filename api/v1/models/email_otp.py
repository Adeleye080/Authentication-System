"""Email OTP Codes Class"""

from sqlalchemy import Column, String, ForeignKey, Integer, DateTime, func
from api.v1.models.base_model import Base
import hashlib


class EmailOtpCodes(Base):
    __tablename__ = "auth_email_otp_codes"

    id = Column(Integer, nullable=False, autoincrement=True, primary_key=True)
    user_id = Column(
        String(36),
        ForeignKey("auth_users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    code_hash = Column(String(64), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    @classmethod
    def create(cls, code: str, user_id: str):
        """Use to create Email OTP instance"""
        code_hash = hashlib.sha256(f"{code}:{user_id}".encode()).hexdigest()
        return cls(user_id=user_id, code_hash=code_hash)

    def __repr__(self):
        return f"<UserEmailCode(id={self.id}, user_id={self.user_id}, created_at={self.created_at.isoformat()})>"
