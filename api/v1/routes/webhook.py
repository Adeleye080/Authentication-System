from fastapi import APIRouter, status, Depends, BackgroundTasks
from db.database import get_db
from sqlalchemy.orm import Session
from api.v1.models.user import User
from api.utils.json_response import JsonResponseDict
from api.v1.services import notification_service, webhook_service, user_service
from api.v1.schemas.webhook import WebhookUrlCreate


webhook_router = APIRouter(prefix="/webhook", tags=["Webhook Management"])


@webhook_router.post(
    "/add", status_code=status.HTTP_201_CREATED, summary="Add webhook url"
)
async def add_webhook_url(
    data: WebhookUrlCreate,
    bgt: BackgroundTasks,
    db: Session = Depends(get_db),
    superadmin: User = Depends(user_service.get_current_superadmin),
):
    """
    Add webhook URL where event data will be sent\n
    use locahost url if you are testing.
    """

    await webhook_service.add_webhook_url(db=db, url=data.url)

    return JsonResponseDict(
        message=f"Webhook URL ({data.url}) added successfully",
        status_code=status.HTTP_201_CREATED,
    )


@webhook_router.put(
    "/update", status_code=status.HTTP_200_OK, summary="Update webhook url"
)
async def update_webhook_url(
    data: WebhookUrlCreate,
    db: Session = Depends(get_db),
    superadmin: User = Depends(user_service.get_current_superadmin),
):
    """update webhook url"""

    old_webhook_url = await webhook_service.change_webhook_url(db=db, url=data.url)

    return JsonResponseDict(
        message=f"Webhook URL updated from ({old_webhook_url}) to ({data.url}) successfully",
        status_code=status.HTTP_200_OK,
    )


@webhook_router.delete(
    "/delete", status_code=status.HTTP_200_OK, summary="Delete webhook url"
)
async def delete_webhook(
    db: Session = Depends(get_db),
    superadmin: User = Depends(user_service.get_current_superadmin),
):
    """delete webhook url"""

    webhook_url = await webhook_service.remove_webhook_url(db)

    return JsonResponseDict(
        message=f"Webhook URL ({webhook_url}) deleted successfully",
        status_code=status.HTTP_200_OK,
    )
