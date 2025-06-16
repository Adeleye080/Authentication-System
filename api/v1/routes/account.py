from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from api.v1.services import user_service, notification_service
from api.v1.models.user import User
from api.v1.schemas.account import AccountReactivationRequest
from api.utils.json_response import JsonResponseDict
from db.database import get_db
from sqlalchemy.orm import Session


account_router = APIRouter(prefix="/accounts")


@account_router.post(
    "/reactivation-request", status_code=status.HTTP_200_OK, tags=["Account"]
)
def request_reactivation_link(
    data: AccountReactivationRequest,
    bgt: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Request a reactivation link for self account reactivation"""

    user_obj = None

    try:
        user_obj = user_service.fetch(email=data.email, db=db)
    except Exception:
        pass

    if user_obj:
        notification_service.send_account_reactivation_link(user=user_obj, bgt=bgt)

    return JsonResponseDict(
        message="If the account exists and is deactivated, you'll receive a reactivation link.",
        status_code=status.HTTP_200_OK,
    )


@account_router.post("/reactivate", status_code=status.HTTP_200_OK, tags=["Account"])
async def self_reactivate_user(
    token: str,
    db: Session = Depends(get_db),
):
    """
    Deactivate an Auth user.
    """

    try:
        # user = user_service.deactivate(db=db, user_id=user.id)
        pass
    except HTTPException as exc:
        return JsonResponseDict(
            message="Failed to deactivate user",
            error=f"{exc.detail}",
            status_code=exc.status_code,
        )

    # return user.to_dict()


@account_router.post(
    "/activate/{user_id}", status_code=status.HTTP_200_OK, tags=["Account"]
)
async def activate_auth_user(
    user: User = Depends(user_service.get_current_user),
    db: Session = Depends(get_db),
    moderator_superadmin: User = Depends(user_service.get_current_user),
):
    """
    Activate an Auth user.
    """

    if not any([moderator_superadmin.is_superadmin, moderator_superadmin.is_moderator]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Not enough permissions."
        )

    try:
        # user = user_service.deactivate(db=db, user_id=user.id)
        pass
    except HTTPException as exc:
        return JsonResponseDict(
            message="Failed to deactivate user",
            error=f"{exc.detail}",
            status_code=exc.status_code,
        )

    # return user.to_dict()


@account_router.post("/deactivate", status_code=status.HTTP_200_OK, tags=["Account"])
def self_deactivation(user: User = Depends(user_service.get_current_user)):
    """ """

    pass


@account_router.post(
    "/deactivate/{user_id}", status_code=status.HTTP_200_OK, tags=["Account"]
)
def deactivate_a_user_auth_account(
    moderator_superadmin: User = Depends(user_service.get_current_user),
    db: Session = Depends(get_db),
):
    """ """

    pass
