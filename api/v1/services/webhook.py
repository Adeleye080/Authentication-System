from sqlalchemy.orm import Session


class WebhookService:

    async def add_webhook_url(self, db: Session, url: str) -> None:
        """Add a webhook url"""

        pass

    async def remove_webhook_url(self, db: Session) -> None:
        """remove webhook URL"""

        pass

    async def change_webhook_url(self, db: Session, url: str) -> None:
        """Change webhook URL"""

        pass
