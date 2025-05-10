"""
Audit Logging Module
"""

from sqlalchemy.orm import Session
from sqlalchemy import func
from fastapi import HTTPException, status
from fastapi import BackgroundTasks
from db.database import get_db
import logging
from typing import List, Tuple
from api.v1.models.audit_logs import AuditLog
from api.v1.schemas.audit_logs import AuditLogSchema, AuditLogCreate


logger = logging.getLogger(__name__)


class AuditLogService:
    """ """

    def get(self, db: Session, log_id: str):
        """Get A single Audit Log"""

        log = db.query(AuditLog).filter_by(AuditLog.id == log_id).first()
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
    ):
        """Create new log entry in the background"""

        background_task.add_task(self.create, db=db, schema=schema)
        return None

    def log_without_bgt(self, schema: AuditLogCreate):
        """Create new log entry without using background task"""

        log = AuditLog(**schema.model_dump(exclude_unset=True))

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
            db_generator.close()

        return log

    def retrieve_user_logs(
        self, db: Session, user_id: str, page: int = 1, per_page: int = 50
    ) -> Tuple[List[AuditLog], any]:
        """Retrieves logs belonging to a user

        Args:
            - page: page number
            - per_page: number of items per page

        Returns:
        """
        # Calculate the offset for pagination
        offset = (page - 1) * per_page

        logs = (
            db.query(AuditLog)
            .filter(AuditLog.user_id == user_id)
            .offset(offset)
            .limit(per_page)
            .all()
        )

        # Query to get the total number of logs
        total_logs = db.query(func.count(AuditLog.id)).scalar()

        return logs, total_logs
