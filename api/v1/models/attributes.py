from api.v1.models.base_model import BaseModel
from sqlalchemy import Column, String, ForeignKey, Index


class UserAttribute(BaseModel):
    __tablename__ = "auth_user_attributes"

    user_id = Column(ForeignKey("auth_users.id"), nullable=False)
    key = Column(String(128), nullable=False)
    value = Column(String(256), nullable=False)

    __table_args__ = (
        Index("ix_auth_user_attribute_key", "key"),
        Index("ix_auth_user_attribute_value", "value"),
    )
