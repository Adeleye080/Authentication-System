from sqlalchemy import Column, Boolean, String, Index
from sqlalchemy.orm import relationship
from db.database import Base
from models.base_model import BaseModel
from schemas.user import RoleEnum
from enum import Enum


class User(BaseModel, Base):
    __tablename__ = "users"

    email = Column(String(128), unique=True, nullable=False)
    recovery_email = Column(String(128), nullable=True)
    password = Column(String(256), nullable=False, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    is_deleted = Column(Boolean, default=False, nullable=False)
    role = Column(Enum(RoleEnum), default=RoleEnum.USER, nullable=False)

    __table_args__ = (
        Index("ix_user_email", "email"),
        Index("ix_user_recovery_email", "recovery_email"),
        Index("ix_user_role", "role"),
        Index("ix_user_is_active", "is_active"),
        Index("ix_user_is_verified", "is_verified"),
        Index("ix_user_is_deleted", "is_deleted"),
    )

    refresh_tokens = relationship("RefreshToken", back_populates="user")

    def to_dict(self):
        obj_dict = super().to_dict()
        obj_dict.pop("password")
        return obj_dict

    def __str__(self):
        return self.email
