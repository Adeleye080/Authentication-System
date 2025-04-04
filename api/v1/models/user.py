from sqlalchemy import Column, Boolean, String, Index, Enum, DateTime
from sqlalchemy.orm import relationship
from api.v1.models.base_model import BaseModel
from api.v1.schemas.user import RoleEnum, LoginSource
from sqlalchemy.orm import Session


class User(BaseModel):
    __tablename__ = "users"

    username = Column(String(128), unique=True, nullable=False)
    email = Column(String(128), unique=True, nullable=False)
    recovery_email = Column(String(128), nullable=True)
    password = Column(String(256), nullable=False)
    is_active = Column(Boolean, default=False, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    is_deleted = Column(Boolean, default=False, nullable=False)
    role = Column(Enum(RoleEnum), default=RoleEnum.USER, nullable=False)
    login_initiated = Column(Boolean, default=False, nullable=False)
    last_login = Column(DateTime, nullable=True)
    login_source = Column(Enum(LoginSource), nullable=True)
    refresh_tokens = relationship("RefreshToken", back_populates="user", uselist=True)
    devices = relationship("Device", backref="user", uselist=True)

    __table_args__ = (
        Index("ix_user_username", "username"),
        Index("ix_user_email", "email"),
        Index("ix_user_recovery_email", "recovery_email"),
        Index("ix_user_role", "role"),
        Index("ix_user_is_active", "is_active"),
        Index("ix_user_is_verified", "is_verified"),
        Index("ix_user_is_deleted", "is_deleted"),
        Index("ix_user_login_initiated", "login_initiated"),
        Index("ix_user_last_login", "last_login"),
        Index("ix_user_login_source", "login_source"),
    )

    def to_dict(self):
        obj_dict = super().to_dict()
        if obj_dict.get("password", False):
            obj_dict.pop("password")
        return obj_dict

    def __str__(self):
        return self.email

    def __repr__(self):
        return f"<User(id={self.id}, email={self.email}, role={self.role})>"

    def save(self, db: Session):
        """save changes made to user object to database"""

        db.add(self)
        db.commit()
