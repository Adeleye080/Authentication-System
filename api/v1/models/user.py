from sqlalchemy import Column, Boolean, DateTime, String
from sqlalchemy.orm import relationship
from db.database import Base
from models.base_model import BaseModel
from sqlalchemy.sql import func


class User(BaseModel, Base):
    __tablename__ = "users"

    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    is_deleted = Column(Boolean, default=False)
    created_at = Column(DateTime, server_default=func.now())

    tokens = relationship("RefreshToken", back_populates="user")
