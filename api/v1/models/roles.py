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

    def to_dict(
        self, hide_creator: bool = False, hide_desc: bool = False, hide_id: bool = False
    ) -> dict:
        """
        Convert object to dictionary

        Args:
        :param hide_creator: hide the creator id
        :param hide_desc: hide the role description
        :param hide_id: hide the role id
        """

        obj_dict = self.__dict__.copy()
        if obj_dict["_sa_instance_state"]:
            del obj_dict["_sa_instance_state"]
        if self.created_at:
            obj_dict["created_at"] = self.created_at.isoformat()

        # Hide options
        if hide_creator:
            del obj_dict["created_by"]
        if hide_desc:
            del obj_dict["description"]
        if hide_id:
            del obj_dict["id"]
        return obj_dict
