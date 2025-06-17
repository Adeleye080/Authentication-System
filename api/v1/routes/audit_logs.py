from fastapi import APIRouter, status, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime
from api.v1.schemas.audit_logs import AllLogsResponse
from api.utils.responses import all_logs_response
from db.database import get_db
from api.v1.services import user_service, audit_log_service
from api.v1.models.user import User


audit_log_router = APIRouter(prefix="/logs", tags=["Audit Logs"])


@audit_log_router.get(
    "",
    summary="Fetch all audit logs",
    status_code=status.HTTP_200_OK,
    response_model=AllLogsResponse,
)
def fetch_all_audit_logs(
    user_id: Optional[str] = Query(None),
    event: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    start_time: Optional[datetime] = Query(None),
    end_time: Optional[datetime] = Query(None),
    page: int = 1,
    per_page: int = 100,
    db: Session = Depends(get_db),
    moderator_superadmin: User = Depends(user_service.get_current_user),
):
    """Fetches all audit logs"""

    if not any([moderator_superadmin.is_superadmin, moderator_superadmin.is_moderator]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Not enough permissions."
        )

    page = max(page, 1)
    per_page = max(per_page, 1)
    if per_page > 100:
        per_page = 100

    if event:
        event = event.upper()
    if status:
        status = status.upper()

    logs, total_logs = audit_log_service.fetch_logs_with_filters_and_pagination(
        db=db,
        user_id=user_id,
        event=event,
        status=status,
        start_time=start_time,
        end_time=end_time,
        page=page,
        limit=per_page,
    )

    logs_count = len(logs)
    total_pages = (total_logs + per_page - 1) // per_page

    return all_logs_response(
        current_page=page,
        per_page=per_page,
        total=total_logs,
        total_pages=total_pages,
        count=logs_count,
        status_code=200,
        data=[log.to_dict() for log in logs],
        prev_page=f"/?page={page - 1}" if page > 1 else None,
        next_page=f"/?page={page + 1}" if page < total_pages else None,
    )


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
