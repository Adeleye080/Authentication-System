"""
Audit Logging Module
"""

from sqlalchemy.orm import Session
from sqlalchemy import func, desc, and_
from fastapi import HTTPException, status
from fastapi import BackgroundTasks
from db.database import get_db
import logging
from typing import List, Tuple, Optional
from datetime import datetime
from api.v1.models.audit_logs import AuditLog
from api.v1.schemas.audit_logs import AuditLogSchema, AuditLogCreate


logger = logging.getLogger(__name__)


class AuditLogService:
    """Audit Logs Service"""

    def get(self, db: Session, log_id: int):
        """Get A single Audit Log"""

        log = db.query(AuditLog).filter(AuditLog.id == log_id).first()
        if not log:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No Log with the identifier {log_id}",
            )
        return log

    def get_all(self, db: Session):
        """
        Retrieve all Logs.

        SHOULD NOT BE USED UNLESS INTENTIONAL
        """

        logs = db.query(AuditLog).all()
        if not logs or len(logs) == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="No Logs Found"
            )

        return logs

    def fetch_logs_with_filters_and_pagination(
        self,
        db: Session,
        user_id: Optional[str] = None,
        event: Optional[str] = None,
        status: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        page: int = 1,
        limit: int = 100,
    ) -> Tuple[str, str]:
        """
        Fetch audit logs with optional filters and pagination.

        Returns a tuple (logs, logs_count)
        """
        query = db.query(AuditLog)
        conditions = []
        offset = (page - 1) * limit

        if event:
            conditions.append(AuditLog.event == event)
        if user_id:
            conditions.append(AuditLog.user_id == user_id)
        if status:
            conditions.append(AuditLog.status == status)
        if start_time:
            conditions.append(AuditLog.timestamp >= start_time)
        if end_time:
            conditions.append(AuditLog.timestamp <= end_time)

        if conditions:
            query = query.filter(and_(*conditions))

        query = query.order_by(AuditLog.id.desc())
        total = query.count()
        logs = query.offset(offset).limit(limit).all()

        return logs, total

    def create(self, db: Session, schema: AuditLogCreate):
        """
        Create a new Audit log
        """

        log = AuditLog(**schema.model_dump(exclude_unset=True))

        try:
            db.add(log)
            db.commit()
            db.refresh(log)
        except Exception as exc:
            logger.error(
                f"Failed to audit log event ({schema.event}) with audit status '{schema.status}' for user with ID {schema.user_id}. error is {exc}"
            )

        return log

    def log(
        self, db: Session, schema: AuditLogCreate, background_task: BackgroundTasks
    ) -> None:
        """Create new log entry in the background"""

        background_task.add_task(self.create, db=db, schema=schema)

    def log_without_bgt(self, schema: Optional[AuditLogCreate], db: Session = None):
        """
        Create new log entry without using background task\n
        db is also optional
        """

        log = AuditLog(**schema.model_dump(exclude_unset=True))

        db_generator = None

        if not db:
            db_generator = get_db()
            db = next(db_generator)

        try:
            db.add(log)
            db.commit()
            db.refresh(log)
        except Exception as exc:
            logger.error(
                f"Failed to audit log event ({schema.event}) with audit status '{schema.status}' for user with ID {schema.user_id}. error is {exc}"
            )
        finally:
            if db_generator:
                db_generator.close()

        return log
