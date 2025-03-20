from fastapi import APIRouter, status, Depends, HTTPException
from sqlalchemy.orm import Session
from db.database import get_db
from api.v1.schemas.audit_logs import AuditLogSchema
from api.utils.json_response import JsonResponseDict


audit_log_router = APIRouter(prefix="/logs", tags=["Audit Logs"])


@audit_log_router.get(
    "/", summary="Fetch all audit logs", status_code=status.HTTP_200_OK
)
def fetch_all_audit_logs(db: Session = Depends(get_db)):
    """Fetches all audit logs"""
    pass


@audit_log_router.get(
    "/{log_id}", summary="Fetch a single audit log", status_code=status.HTTP_200_OK
)
def fetch_single_audit_log(log_id: int, db: Session = Depends(get_db)):
    """Fetches a single audit log"""
    pass


@audit_log_router.get(
    "/user/{user_id}",
    summary="Fetch all audit logs for a user",
    status_code=status.HTTP_200_OK,
)
def fetch_user_audit_logs(user_id: int, db: Session = Depends(get_db)):
    """Fetches all audit logs for a user"""
    pass
