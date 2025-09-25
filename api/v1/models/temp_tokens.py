from sqlalchemy import Column, String, DateTime, Integer, Index
from api.v1.models.base_model import Base
from db.database import get_db


class TempToken(Base):
    """Temporary token Model for tracking temporary tokens"""

    __tablename__ = "auth_temp_tokens"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    token = Column(String(400), nullable=False)
    user_identifier = Column(String(150), nullable=False)  # email or ID
    expires_at = Column(DateTime(timezone=True), nullable=False)

    __table__args__ = (Index("idx_user_identifier", "user_identifier"),)

    def __repr__(self):
        return f"<TempToken id={self.id} user_identifier={self.user_identifier} expires_at={self.expires_at}>"

    def __str__(self):
        return self.token

    def save(self, db):
        """Save the TempToken to the database."""
        db_generator = get_db()
        try:
            db = next(db_generator)
            db.add(self)
            db.commit()
            db.refresh(self)
        finally:
            db_generator.close()
        return self
