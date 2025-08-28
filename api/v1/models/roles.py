"""Role models module."""

from sqlalchemy import Column, Integer, String, Index, Table, ForeignKey
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
    name = Column(String(128), nullable=False)
    description = Column(String(258), nullable=True)

    __table_args__ = (Index("user_secondary_role", "name"),)
