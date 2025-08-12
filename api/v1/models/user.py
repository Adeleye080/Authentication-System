from sqlalchemy import Column, Boolean, String, Index, Enum, DateTime, LargeBinary
from sqlalchemy.orm import relationship
from api.v1.models.base_model import BaseModel
from api.v1.schemas.user import LoginSource
from sqlalchemy.orm import Session
from pydantic import EmailStr
from typing import Tuple


class User(BaseModel):
    __tablename__ = "auth_users"

    email = Column(String(128), unique=True, nullable=False)
    recovery_email = Column(String(128), nullable=True)
    password = Column(String(256), nullable=False)
    is_active = Column(Boolean, default=False, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    is_deleted = Column(Boolean, default=False, nullable=False)
    is_superadmin = Column(Boolean, default=False, nullable=False)
    is_moderator = Column(Boolean, default=False, nullable=False)
    login_initiated = Column(Boolean, default=False, nullable=False)
    last_login = Column(DateTime, nullable=True)
    login_source = Column(Enum(LoginSource), nullable=True)
    is_banned = Column(Boolean, default=False, nullable=False)
    secondary_role = Column(String(128), nullable=True)

    attributes = relationship("UserAttribute", backref="user", uselist=True)

    refresh_tokens = relationship(
        "RefreshToken",
        back_populates="user",
        uselist=True,
        cascade="all, delete-orphan",
    )
    devices = relationship(
        "Device", backref="user", uselist=True, cascade="all, delete-orphan"
    )
    totp_device = relationship(
        "TOTPDevice", backref="user", uselist=False, cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_user_email", "email"),
        Index("ix_user_recovery_email", "recovery_email"),
        Index("ix_user_is_active", "is_active"),
        Index("ix_user_is_verified", "is_verified"),
        Index("ix_user_is_deleted", "is_deleted"),
        Index("ix_user_login_initiated", "login_initiated"),
        Index("ix_user_last_login", "last_login"),
        Index("ix_user_login_source", "login_source"),
        Index("ix_user_is_banned", "is_banned"),
        Index("ix_user_is_superadmin", "is_superadmin"),
        Index("ix_user_is_moderator", "is_moderator"),
        Index("ix_user_secondary_role", "secondary_role"),
    )

    def to_dict(self, hide_sensitive_data: bool = True):
        obj_dict = super().to_dict()
        if obj_dict.get("password", False):
            obj_dict.pop("password")

        if hide_sensitive_data:
            # hide all other sensitive data
            if "login_initiated" in obj_dict.keys():
                del obj_dict["login_initiated"]
            if "is_deleted" in obj_dict.keys():
                del obj_dict["is_deleted"]
            if "is_moderator" in obj_dict.keys():
                del obj_dict["is_moderator"]
            if "is_superadmin" in obj_dict.keys():
                del obj_dict["is_superadmin"]
            if "secondary_role" in obj_dict.keys():
                del obj_dict["secondary_role"]
            if "is_banned" in obj_dict.keys():
                del obj_dict["is_banned"]

        return obj_dict

    def __str__(self):
        return self.email

    def __repr__(self):
        return f"<User(id={self.id}, email={self.email}, role={self.role})>"

    def save(self, db: Session):
        """save changes made to user object to database"""

        db.add(self)
        db.commit()
        db.refresh(self)

    def user_exists(
        self, db: Session, id: str = None, email: EmailStr = None
    ) -> Tuple[bool, dict]:
        """
        Check if user exists in the database with the given email or ID.
        If both are given, it will check for the first one that is found.

        :param db: Database session
        :param email: User email
        :param id: User ID

        :return: (True, user_obj) if user exists, (False, {}) otherwise
        """

        if not any([email, id]):
            raise ValueError("At least email or id must be provided.")

        # initialize user to None
        user = None

        if id:
            # user = db.get(User, ident=id)
            user = db.query(User).filter_by(id=id).first()

        elif email:
            user = db.query(User).filter_by(email=email).first()

        if user:
            return (True, user.to_dict())

        return False, {}
