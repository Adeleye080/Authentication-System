"""Role models module."""

from sqlalchemy import Column, Integer, String, Index, Table, ForeignKey, DateTime, func
from db.database import Base


auth_user_roles_association = Table(
    "auth_user_roles_association",
    Base.metadata,
    Column("auth_user_id", ForeignKey("auth_users.id"), primary_key=True),
    Column(
        "auth_user_role_id", ForeignKey("auth_secondary_roles.id"), primary_key=True
    ),
)


class SecondaryRole(Base):
    """Secondary role model"""

    __tablename__ = "auth_secondary_roles"

    id = Column(Integer, primary_key=True, nullable=False, autoincrement=True)
    name = Column(String(128), nullable=False, unique=True)
    description = Column(String(258), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    created_by = Column(String(36), nullable=False)

    __table_args__ = (Index("user_secondary_role", "name"),)
