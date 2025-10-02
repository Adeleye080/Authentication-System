import strawberry
from fastapi import Depends
from sqlalchemy.orm import Session
from typing import List
from api.graphql.types.audit_log import AuditLogType
from api.v1.services import audit_log_service
from api.v1.models.user import User
from api.v1.services import user_service
from api.graphql.utils.permissions import require_admin
from db.database import get_db


@strawberry.type
class AuditLogQueries:
    @strawberry.field
    def audit_logs(self, info) -> List[AuditLogType]:
        context = info.context
        current_user = context.get("current_user")
        db = context.get("db")

        # only admin can access
        require_admin(current_user)
        # fetch logs
        logs = audit_log_service.get_all(db)

        return [
            AuditLogType(
                id=log.id,
                user_id=log.user_id,
                event=log.event,
                description=log.description,
                status=log.status,
                ip_address=log.ip_address,
                user_agent=log.user_agent,
                timestamp=log.timestamp,
                details=log.details,
            )
            for log in logs
        ]
