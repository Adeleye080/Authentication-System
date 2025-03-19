from fastapi import APIRouter, Depends, HTTPException, status
from db.database import get_db
from sqlalchemy.orm import Session


oauth_router = APIRouter(tags=["OAuth"], prefix="/oauth")


@oauth_router.get(
    "/providers",
    summary="Get list of available OAuth providers",
    status_code=status.HTTP_200_OK,
)
def get_oauth_providers(db: Session = Depends(get_db)):
    """Get list of available OAuth providers"""
    pass
