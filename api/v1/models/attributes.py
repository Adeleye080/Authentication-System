from api.v1.models.base_model import BaseModel, Base
from sqlalchemy import Column, Integer, String, ForeignKey, Index
from sqlalchemy.orm import relationship


class AttributeValues(Base):
    __tablename__ = "auth_predefined_attr_vals"

    id = Column(Integer, autoincrement=True, primary_key=True)
    attribute_id = Column(
        Integer, ForeignKey("auth_user_attributes.id"), nullable=False
    )
    value = Column(String(100), nullable=False)


class Attributes(Base):
    __tablename__ = "auth_user_attributes"

    id = Column(Integer, autoincrement=True, primary_key=True)
    name = Column(String(60), nullable=False, unique=True)

    allowed_values = relationship(
        AttributeValues, backref="attribute", cascade="all, delete-orphan", uselist=True
    )

    __table_args__ = (Index("ix_auth_user_attributes_name", "name", unique=True),)


class UserAttribute(BaseModel):
    __tablename__ = "auth_user_attrs_association"

    user_id = Column(ForeignKey("auth_users.id"), nullable=False, primary_key=True)
    attribute_id = Column(
        Integer, ForeignKey("auth_user_attributes.id"), nullable=False, primary_key=True
    )
    attribute_value_id = Column(
        ForeignKey("auth_predefined_attr_vals.id"), nullable=False
    )

    attribute = relationship("Attributes", backref="user_attributes_link")
    attribute_value = relationship("AttributeValues", backref="user_attributes_link")
