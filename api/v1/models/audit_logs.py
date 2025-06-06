from sqlalchemy import Column, String, Text, JSON, DateTime, func, Index, Integer
from db.database import Base
from fastapi import Depends


class AuditLog(Base):
    """Audit Log Model"""

    __tablename__ = "auth_audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(36), nullable=False)
    event = Column(String(100), nullable=False)
    status = Column(String(50), nullable=False)
    description = Column(Text, nullable=False)
    timestamp = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    details = Column(JSON, nullable=True)
    ip_address = Column(String(50), nullable=True)
    user_agent = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_audit_log_id", "id"),
        Index("ix_audit_log_user_id", "user_id"),
        Index("ix_audit_log_event", "event"),
        Index("ix_audit_log_status", "status"),
        Index("ix_audit_log_timestamp", "timestamp"),
        Index("ix_audit_log_user_ip_address", "ip_address"),
    )

    def __repr__(self):
        return f"<AuditLog {self.id}>"

    def to_dict(self):
        """returns a dictionary representation of the audit log instance"""
        obj_dict = self.__dict__.copy()
        if obj_dict["_sa_instance_state"]:
            del obj_dict["_sa_instance_state"]
        if self.timestamp:
            obj_dict["timestamp"] = self.timestamp.isoformat()
        return obj_dict

    @classmethod
    def get_for_user(cls, user_id):
        """returns all audit logs for a user"""
        from db.database import get_db

        db = Depends(get_db)
        return db.query(cls).filter_by(user_id=user_id).all()
