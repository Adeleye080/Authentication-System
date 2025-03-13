from sqlalchemy import Column, Boolean, String, Index, Enum
from sqlalchemy.orm import relationship
from db.database import Base
from api.v1.models.base_model import BaseModel
from api.v1.schemas.user import RoleEnum

# call below line to ensure RefreshToken is found by mapper
from api.v1.models.refresh_token import RefreshToken


class User(BaseModel):
    __tablename__ = "users"

    email = Column(String(128), unique=True, nullable=False)
    recovery_email = Column(String(128), nullable=True)
    password = Column(String(256), nullable=False)
    is_active = Column(Boolean, default=False, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    is_deleted = Column(Boolean, default=False, nullable=False)
    role = Column(Enum(RoleEnum), default=RoleEnum.USER, nullable=False)
    refresh_tokens = relationship("RefreshToken", back_populates="user", uselist=True)

    __table_args__ = (
        Index("ix_user_email", "email"),
        Index("ix_user_recovery_email", "recovery_email"),
        Index("ix_user_role", "role"),
        Index("ix_user_is_active", "is_active"),
        Index("ix_user_is_verified", "is_verified"),
        Index("ix_user_is_deleted", "is_deleted"),
    )

    def to_dict(self):
        obj_dict = super().to_dict()
        obj_dict.pop("password")
        return obj_dict

    def __str__(self):
        return self.email
