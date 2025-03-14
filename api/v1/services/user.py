from fastapi import HTTPException, Depends, Request, status
from fastapi.security import OAuth2PasswordBearer

from passlib.context import CryptContext
from typing import Tuple, Optional
from sqlalchemy.orm import Session
from db.database import get_db
import datetime as dt
from jose import JWTError, jwt
from sqlalchemy import func

from api.utils.settings import settings
from api.v1.models.user import User
from api.v1.schemas.user import (
    UserCreate,
    UserResponseModel,
    AccessTokenData,
    DeactivateUserSchema,
    UserUpdateSchema,
)
from api.core.base.services import Service
from api.utils.validators import check_model_existence


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class UserService(Service):
    """Auth user service"""

    def create(self, db: Session, schema: UserCreate):
        """Creates a Auth new user"""

        if db.query(User).filter(User.email == schema.email).first():
            raise HTTPException(
                status_code=400,
                detail="User with this email already exists",
            )

        # Hash password
        schema.password = self.hash_password(password=schema.password)

        # Create auth user object with hashed password and other attributes from schema
        try:
            user = User(**schema.model_dump())
            db.add(user)
            db.commit()
            db.refresh(user)
        except Exception as exc:
            raise HTTPException(status_code=500, detail="There was a database error")

        return user

    def fetch(self, db: Session, schema: UserResponseModel):
        """fetch a single user from the system"""

        user = db.query(User).filter(User.email == schema.email).first()
        if not user:
            raise HTTPException(
                status_code=404, detail="Auth user does not exist in our system!"
            )
        return user

    def fetch_all(self, db: Session):
        """fetch all auth user in the system"""

        all_users = db.query(User).all()
        return all_users

    def fetch_all_paginated(self, db: Session, page: int, per_page: int):
        """
        Fetch all auth user in the system

        Args:
            :param page: int: page number
            :param per_page: int: number of items per page

        Returns:
            :return: Tuple[User, int]: Tuple of users and total number of users
        """

        # Calculate the offset for pagination
        offset = (page - 1) * per_page

        # Query to get paginated users
        users = db.query(User).offset(offset).limit(per_page).all()

        # Query to get the total number of users
        total = db.query(func.count(User.id)).scalar()

        return users, total

    def update(self, db: Session, user_id: str, schema: UserUpdateSchema):
        """Update an Auth user data

        Args:
            db (Session): Database session.
            user_id (str): ID of the user to update.
            schema (UserUpdateSchema): Pydantic schema containing fields to update.

        Returns:
            User: The updated user object.
        """

        # Find the user by ID
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Convert the schema to a dictionary (excluding unset fields)
        update_data = schema.dict(exclude_unset=True)

        # Update the user fields
        for key, value in update_data.items():
            setattr(user, key, value)

        db.commit()
        db.refresh(user)

        return user

    def delete(self, db: Session, schema: UserResponseModel):
        """
        deletes an auth user from the system
        """
        pass

    def authenticate_user(self, db: Session, email: str, password: str):
        """Function to authenticate a user"""

        user = db.query(User).filter(User.email == email).first()

        if not user:
            raise HTTPException(status_code=400, detail="Invalid user credentials")

        if not self.verify_password(password, user.password):
            raise HTTPException(status_code=400, detail="Invalid user credentials")

        return user

    def perform_user_check(self, user: User):
        """This checks if a user is active and verified and not a deleted user"""

        if not user.is_active:
            raise HTTPException(detail="User is not active", status_code=403)

    def hash_password(self, password: str) -> str:
        """Function to hash a password"""

        hashed_password = pwd_context.hash(secret=password)
        return hashed_password

    def verify_password(self, password: str, hash: str) -> bool:
        """Function to verify a hashed password"""

        return pwd_context.verify(secret=password, hash=hash)

    def create_access_token(self, user_id: str) -> str:
        """Function to create access token"""

        expires = dt.datetime.now(dt.timezone.utc) + dt.timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
        data = {"sub": user_id, "exp": expires, "type": "access"}
        encoded_jwt = jwt.encode(data, settings.SECRET_KEY, settings.ALGORITHM)
        return encoded_jwt

    def create_refresh_token(self, user_id: str) -> str:
        """Function to create access token"""

        expires = dt.datetime.now(dt.timezone.utc) + dt.timedelta(
            days=settings.JWT_REFRESH_EXPIRY
        )
        data = {"user_id": user_id, "exp": expires, "type": "refresh"}
        encoded_jwt = jwt.encode(data, settings.SECRET_KEY, settings.ALGORITHM)
        return encoded_jwt

    def verify_access_token(self, access_token: str, credentials_exception):
        """Funtcion to decode and verify access token"""

        try:
            payload = jwt.decode(
                access_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
            )
            user_id = payload.get("user_id")
            token_type = payload.get("type")

            if user_id is None:
                raise credentials_exception

            if token_type == "refresh":
                raise HTTPException(detail="Refresh token not allowed", status_code=400)

            token_data = AccessTokenData(id=user_id)

        except JWTError as err:
            print(err)
            raise credentials_exception

        return token_data

    def verify_refresh_token(self, refresh_token: str, credentials_exception):
        """Funtcion to decode and verify refresh token"""

        try:
            payload = jwt.decode(
                refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
            )
            user_id = payload.get("user_id")
            token_type = payload.get("type")

            if user_id is None:
                raise credentials_exception

            if token_type == "access":
                raise HTTPException(detail="Access token not allowed", status_code=400)

            token_data = AccessTokenData(id=user_id)

        except JWTError:
            raise credentials_exception

        return token_data

    def refresh_access_token(self, current_refresh_token: str):
        """Function to generate new access token and rotate refresh token"""

        credentials_exception = HTTPException(
            status_code=401, detail="Refresh token expired"
        )

        token = self.verify_refresh_token(current_refresh_token, credentials_exception)

        if token:
            access = self.create_access_token(user_id=token.id)
            refresh = self.create_refresh_token(user_id=token.id)

            return access, refresh

    def get_current_user(
        self, access_token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
    ) -> User:
        """Function to get current logged in user"""

        credentials_exception = HTTPException(
            status_code=401,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

        token = self.verify_access_token(access_token, credentials_exception)
        user = db.query(User).filter(User.id == token.id).first()

        return user

    def deactivate_user(
        self,
        request: Request,
        db: Session,
        schema: DeactivateUserSchema,
        user: User,
    ):
        """Function to deactivate a user"""

        if not schema.confirmation:
            raise HTTPException(
                detail="Confirmation required to deactivate account", status_code=400
            )

        self.perform_user_check(user)

        user.is_active = False

        # Create reactivation token
        token = self.create_access_token(user_id=user.id)
        reactivation_link = f"https://{request.url.hostname}/api/v1/users/accounts/reactivate?token={token}"

        # mail_service.send_mail(
        #     to=user.email,
        #     subject='Account deactivation',
        #     body=f'Hello, {user.first_name},\n\nYour account has been deactivated successfully.\nTo reactivate your account if this was a mistake, please click the link below:\n{request.url.hostname}/api/users/accounts/reactivate?token={token}\n\nThis link expires after 15 minutes.'
        # )

        db.commit()

        return reactivation_link

    def reactivate_user(self, db: Session, token: str):
        """This function reactivates a user account"""

        # Validate the token
        try:
            payload = jwt.decode(
                token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
            )
            user_id = payload.get("user_id")

            if user_id is None:
                raise HTTPException(400, "Invalid token")

        except JWTError:
            raise HTTPException(400, "Invalid token")

        user = db.query(User).filter(User.id == user_id).first()

        if user.is_active:
            raise HTTPException(400, "User is already active")

        user.is_active = True

        db.commit()

    def change_password(
        self,
        new_password: str,
        user: User,
        db: Session,
        old_password: Optional[str] = None,
    ):
        """Endpoint to change the user's password"""
        if old_password == new_password:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Old Password and New Password cannot be the same",
            )
        if old_password is None:
            if user.password is None:
                user.password = self.hash_password(new_password)
                db.commit()
                return
            else:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="Old Password must not be empty, unless setting password for the first time.",
                )
        elif not self.verify_password(old_password, user.password):
            raise HTTPException(status_code=400, detail="Incorrect old password")
        else:
            user.password = self.hash_password(new_password)
            db.commit()

    # @staticmethod
    # def verify_magic_token(magic_token: str, db: Session) -> Tuple[User, str]:
    #     """Function to verify magic token"""

    #     credentials_exception = HTTPException(
    #         status_code=401,
    #         detail="Could not validate credentials",
    #         headers={"WWW-Authenticate": "Bearer"},
    #     )

    #     token = user_service.verify_access_token(magic_token, credentials_exception)
    #     user = db.query(User).filter(User.id == token.id).first()

    #     return user, magic_token
