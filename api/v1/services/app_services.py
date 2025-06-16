from passlib.context import CryptContext  # type: ignore
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from typing import Tuple, Optional
from fastapi import HTTPException, status
from jose import jwt  # type: ignore
import secrets
import string
from api.utils.settings import settings
from api.v1.models.service_apps import ServiceApp


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class ApplicationService:
    """Service Application Service"""

    def fetch(self, db: Session, service_id: str) -> ServiceApp:
        """Fetch a single app service"""

        app = db.query(ServiceApp).filter(ServiceApp.id == service_id).first()
        if not app:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Service app does not exist",
            )
        return app

    def fetch_all(self, db: Session):
        """Fetch all app services in database"""

        return db.query(ServiceApp).all()

    def verify_app_secret(self, plain_secret, hashed_secret) -> bool:
        return pwd_context.verify(plain_secret, hashed_secret)

    def hash_app_secret(self, secret: str):
        return pwd_context.hash(secret)

    def generate_app_secret(self) -> str:
        """ """
        alphabet = string.ascii_letters + string.digits  # a-z, A-Z, 0-9
        return "service-" + "".join(secrets.choice(alphabet) for _ in range(40))

    def create_app_token(
        self,
        app_service_name: str,
        expires_at_hours: Optional[int] = settings.APP_SERVICE_TOKEN_EXPIRE_HOUR,
    ) -> str:
        """creates app service access token"""

        expires_at = datetime.now(tz=timezone.utc) + timedelta(hours=expires_at_hours)

        to_encode = {"exp": expires_at, "sub": "service:" + app_service_name}

        return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

    def create_app(
        self, db: Session, service_name: str, description: str = None
    ) -> Tuple[str, ServiceApp]:
        """
        creates new app service.

        Returns (app_secret, app_object)
        """

        plain_secret = self.generate_app_secret()
        hashed_secret = self.hash_app_secret(secret=plain_secret)

        new_app_service = ServiceApp(
            name=service_name,
            description=description,
            secret=hashed_secret,
            is_active=False,
        )

        try:
            db.add(new_app_service)
            db.commit()
            db.refresh(new_app_service)
        except IntegrityError:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Service app with the name '{new_app_service.name}' already exist.",
            )
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred, seems to be on our side.",
            )

        return plain_secret, new_app_service

    def check_app_service_status(self, service_app: ServiceApp) -> None:
        """Perform check for app active status"""

        if not service_app.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="App is not active, cannot authenticate",
            )

        return

    def authenticate(self, service_id: str, service_secret: str, db: Session) -> str:
        """
        Authenticate a service

        :param service_id: ID of the service to authenticate
        :param service_secret: Password of the service
        :param db: Database session
        """

        service_app = self.fetch(db=db, service_id=service_id)
        if not self.verify_app_secret(
            plain_secret=service_secret, hashed_secret=service_app.secret
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid service app credentials.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # check service status
        self.check_app_service_status(service_app)

        app_token = self.create_app_token(app_service_name=service_app.name)

        return app_token

    def delete_app(self, db: Session, service_id: str):
        """Delete a service app"""

        service_app = self.fetch(db=db, service_id=service_id)

        db.delete(service_app)
        db.commit()

        return service_app

    def activate(self, service_id: str, db: Session) -> None:
        """Activate an app service"""

        service_app = self.fetch(db=db, service_id=service_id)
        # activate service
        service_app.is_active = True
        # save changes to database
        service_app.save_changes(db=db)

    def deactivate(self, service_id: str, db: Session) -> None:
        """Deactivate an app service"""

        service_app = self.fetch(db=db, service_id=service_id)
        # deactivate service
        service_app.is_active = False
        # save changes to database
        service_app.save_changes(db=db)
