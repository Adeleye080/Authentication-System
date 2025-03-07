from sqlalchemy import Column, Text, Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import relationship
from db.database import Base
from models.base_model import BaseModel


class RefreshToken(BaseModel, Base):
    __tablename__ = "refresh_tokens"

    user_id = Column(String(128), ForeignKey("users.id"), nullable=False)
    token = Column(String(225), unique=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)

    user = relationship("User", back_populates="refresh_tokens")
