"""
Application Services Model

for service to service communication
"""

from api.v1.models.base_model import BaseModel
from sqlalchemy import Column, String, Boolean
from sqlalchemy.orm import Session


class ServiceApp(BaseModel):
    """Service app model"""

    __tablename__ = "auth_service_apps"

    name = Column(String(255), unique=True, nullable=False)
    description = Column(String(1024), nullable=True)
    secret = Column(String(255), nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)

    def to_dict(self):
        """ """
        obj = super().to_dict()

        if obj["secret"]:
            del obj["secret"]

        return obj

    def save_changes(self, db: Session) -> None:
        """Save changes made to database"""

        db.add(self)
        db.commit()
