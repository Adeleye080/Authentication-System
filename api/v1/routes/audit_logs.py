from fastapi import APIRouter, status, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime
from api.v1.schemas.audit_logs import AuditLogEventEnum
from db.database import get_db
from api.v1.services import user_service, audit_log_service
from api.v1.models.user import User


audit_log_router = APIRouter(prefix="/logs", tags=["Audit Logs"])


@audit_log_router.get(
    "/",
    summary="Fetch all audit logs",
    status_code=status.HTTP_200_OK,
)
def fetch_all_audit_logs(
    event: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    start_time: Optional[datetime] = Query(None),
    end_time: Optional[datetime] = Query(None),
    db: Session = Depends(get_db),
    moderator_superadmin: User = Depends(user_service.get_current_user),
):
    """Fetches all audit logs"""

    audit_log_service.get
    pass


@audit_log_router.get(
    "/{log_id}", summary="Fetch a single audit log", status_code=status.HTTP_200_OK
)
def fetch_single_audit_log(
    log_id: int,
    db: Session = Depends(get_db),
    moderator_superadmin: User = Depends(user_service.get_current_user),
):
    """Fetches a single audit log"""

    if not any([moderator_superadmin.is_superadmin, moderator_superadmin.is_moderator]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Not enough permissions."
        )

    single_log = audit_log_service.get(db=db, log_id=log_id)

    return single_log


@audit_log_router.get(
    "/user/{user_id}",
    summary="Fetch all audit logs for a user",
    status_code=status.HTTP_200_OK,
)
def fetch_user_audit_logs(
    user_id: str,
    db: Session = Depends(get_db),
    moderator_superadmin: User = Depends(user_service.get_current_user),
):
    """Fetches all audit logs for a user"""

    # add option to get by status, events, etc.

    # admin only route
    if not any([moderator_superadmin.is_superadmin, moderator_superadmin.is_moderator]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Not enough permissions."
        )

    logs, no_of_logs = audit_log_service.retrieve_user_logs(db=db, user_id=user_id)

    # return paginated data
    return [log.to_dict() for log in logs]
