from fastapi import HTTPException, Depends, Request, status, Security
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext  # type: ignore
from typing import Tuple, Optional, List, Annotated
from pydantic import EmailStr
from sqlalchemy.orm import Session
import datetime as dt
from jose import JWTError, jwt, ExpiredSignatureError  # type: ignore
from sqlalchemy import func
from db.database import get_db

from api.utils.settings import settings
from api.v1.models.user import User
from api.v1.models.refresh_token import RefreshToken
from api.v1.schemas.user import (
    UserCreate,
    UserResponseModel,
    AccessTokenData,
    DeactivateUserSchema,
    UserUpdateSchema,
    RoleEnum,
    LoginSource,
)
from api.core.base.services import Service
from api.utils.validators import check_model_existence
from api.utils.json_response import JsonResponseDict


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/swagger-login")
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
            print(exc)
            raise HTTPException(status_code=500, detail="There was a database error")

        return user

    def fetch(self, db: Session, email: EmailStr):
        """fetch a single user from the system"""

        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(
                status_code=404, detail="Auth user does not exist in our system!"
            )
        return user

    def fetch_all(self, db: Session):
        """fetch all auth user in the system"""

        all_users = db.query(User).all()
        return all_users

    def fetch_all_paginated(self, db: Session, page: int = 1, per_page: int = 10):
        """
        Fetch all auth user in the system with no respect for
        statuses [active status, deletion status, and verification status]

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

    def fetch_all_paginated_with_filters(
        self,
        db: Session,
        page: int,
        per_page: int,
        is_active: Optional[bool] = True,
        is_deleted: Optional[bool] = False,
        is_verified: Optional[bool] = True,
    ) -> Tuple[List[User], int]:
        """
        Fetch all auth users in the system with optional filters.

        Args:
            :param page: int: page number
            :param per_page: int: number of items per page
            :param is_active: Optional[bool]: Filter users based on active status
            :param is_deleted: Optional[bool]: Filter users based on deletion status
            :param is_verified: Optional[bool]: Filter users based on verification status

        Returns:
            :return: Tuple[List[User], int]: Tuple of users and total number of users matching filters
        """
        # Calculate the offset for pagination
        offset = (page - 1) * per_page

        # Base query
        query = db.query(User)

        # Apply optional filters
        if is_active is not None:
            query = query.filter(User.is_active == is_active)
        if is_deleted is not None:
            query = query.filter(User.is_deleted == is_deleted)
        if is_verified is not None:
            query = query.filter(User.is_verified == is_verified)

        # Get paginated users
        users = query.offset(offset).limit(per_page).all()

        # Get the total number of filtered users
        total = (
            db.query(func.count(User.id))
            .filter(
                *(
                    User.is_active == is_active if is_active is not None else True,
                    User.is_deleted == is_deleted if is_deleted is not None else False,
                    (
                        User.is_verified == is_verified
                        if is_verified is not None
                        else True
                    ),
                )
            )
            .scalar()
        )

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
        update_data = schema.model_dump(exclude_unset=True)

        # Update the user fields
        for key, value in update_data.items():
            setattr(user, key, value)

        db.commit()
        db.refresh(user)

        return user

    def delete(self, db: Session, user_id: str):
        """
        deletes an auth user from the system
        """

        user = db.query(User).filter(User.id == user_id).first()

        if not user:
            raise HTTPException(
                detail="User does not exist in our system", status_code=404
            )

        if user.is_deleted is True:
            raise HTTPException(
                detail="Forbidden, User has been previously deleted!", status_code=403
            )

        try:
            setattr(user, "is_deleted", True)
            db.commit()
            db.refresh(user)
        except Exception as exc:
            raise HTTPException(
                status_code=500, detail="Database operation to delete user failed"
            )

        return user

    def authenticate_user(self, db: Session, email: str, password: str):
        """Function to authenticate a user with password"""

        user = db.query(User).filter(User.email == email).first()

        if not user:
            raise HTTPException(status_code=404, detail="User does not exist")

        if not self.verify_password(password, user.password):
            raise HTTPException(status_code=400, detail="Invalid user credentials")

        self.perform_user_check(user)

        user.last_login = dt.datetime.now(dt.timezone.utc)
        user.login_source = LoginSource.PASSWORD
        user.save(db)

        return user

    def authenticate_user_with_magic_link(self, db: Session, magic_token: str) -> User:
        """Function to authenticate a user with magic link"""

        from api.utils.encrypters_and_decrypters import decrypt_magic_link_token

        user_email = decrypt_magic_link_token(magic_token)
        user = db.query(User).filter(User.email == user_email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User does not exist")

        self.perform_user_check(user)

        user.last_login = dt.datetime.now(dt.timezone.utc)
        user.login_source = LoginSource.MAGICLINK
        user.save(db=db)

        return user

    def perform_user_check(self, user: User) -> bool:
        """This checks if a user is active and verified and not a deleted user"""

        if not user.is_verified:
            raise HTTPException(
                detail="User is not verified", status_code=status.HTTP_401_UNAUTHORIZED
            )
        if not user.is_active:
            raise HTTPException(
                detail="User is inactive or banned",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        if user.is_deleted:
            raise HTTPException(
                detail="The account has been deleted. Please contact support if this is a mistake.",
                status_code=status.HTTP_403_FORBIDDEN,
            )

        return True

    def hash_password(self, password: str) -> str:
        """Function to hash a password"""

        hashed_password = pwd_context.hash(secret=password)
        return hashed_password

    def verify_password(self, password: str, hash: str) -> bool:
        """Function to verify a hashed password"""

        return pwd_context.verify(secret=password, hash=hash)

    def create_access_token(self, user_id: str) -> str:
        """Function to create access token"""

        try:
            expires = dt.datetime.now(dt.timezone.utc) + dt.timedelta(
                minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
            )
            data = {"sub": user_id, "exp": expires, "type": "access"}
            encoded_jwt = jwt.encode(data, settings.SECRET_KEY, settings.ALGORITHM)
        except Exception as exc:
            raise HTTPException(
                status_code=500, detail="Failed to generate user access token"
            ) from exc
        return encoded_jwt

    def create_refresh_token(self, db: Session, user_id: str) -> str:
        """Function to create refresh token"""

        expires = dt.datetime.now(dt.timezone.utc) + dt.timedelta(
            days=settings.JWT_REFRESH_EXPIRY
        )
        data = {"sub": user_id, "exp": expires, "type": "refresh"}
        encoded_jwt = jwt.encode(data, settings.SECRET_KEY, settings.ALGORITHM)

        try:
            refresh_token = RefreshToken(
                token=encoded_jwt, user_id=user_id, expires_at=expires
            )
            db.add(refresh_token)
            db.commit()
        except Exception as exc:
            raise HTTPException(
                status_code=500, detail="Failed to save refresh token"
            ) from exc

        return encoded_jwt

    def verify_access_token(self, access_token: str, credentials_exception):
        """Funtcion to decode and verify access token"""

        try:
            payload = jwt.decode(
                access_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
            )
            user_id = payload.get("sub")
            token_type = payload.get("type")

            if user_id is None:
                raise credentials_exception

            if token_type == "refresh":
                raise HTTPException(detail="Refresh token not allowed", status_code=400)

            token_data = AccessTokenData(id=user_id)

        except JWTError as err:
            raise credentials_exception

        return token_data

    def verify_refresh_token(self, refresh_token: str, credentials_exception):
        """Funtcion to decode and verify refresh token"""

        try:
            payload = jwt.decode(
                refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
            )
            user_id = payload.get("sub")
            token_type = payload.get("type")

            if user_id is None:
                raise credentials_exception

            if token_type == "access":
                raise HTTPException(detail="Access token not allowed", status_code=400)

            token_data = AccessTokenData(id=user_id)

        except ExpiredSignatureError as exc:
            raise credentials_exception from exc
        except JWTError as exc:
            raise HTTPException(
                status_code=400, detail="error verifying and decoding refresh token"
            ) from exc

        return token_data

    def revoke_refresh_token(self, db: Session, token: str):
        """Function to revoke refresh token"""

        if not token:
            raise HTTPException(status_code=400, detail="No token provided")

        try:
            payload = jwt.decode(
                token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
            )
            token_id = payload.get("_id")

            if token_id is None:
                raise HTTPException(400, "Invalid token")

        except JWTError as exc:
            raise HTTPException(400, "Invalid token") from exc

        refresh_token = (
            db.query(RefreshToken).filter(RefreshToken.id == token_id).first()
        )

        if not refresh_token:
            raise HTTPException(400, "Invalid token")

        refresh_token.revoked = True
        db.commit()
        db.refresh(refresh_token)
        return True

    def refresh_access_token(self, current_refresh_token: str):
        """Function to generate new access token and rotate refresh token"""

        credentials_exception = HTTPException(
            status_code=401, detail="Refresh token expired"
        )

        token = self.verify_refresh_token(current_refresh_token, credentials_exception)

        if token:
            db: Session = Depends(get_db)
            access = self.create_access_token(user_id=token.id)
            refresh = self.create_refresh_token(db=db, user_id=token.id)

            return (access, refresh)

    def get_current_user(
        self, access_token: str = Security(oauth2_scheme), db: Session = Depends(get_db)
    ) -> User:
        """
        Function to get current logged in user.

        request will fail if user is deactivated or deleted
        """
        try:
            credentials_exception = HTTPException(
                status_code=401,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

            token = self.verify_access_token(access_token, credentials_exception)
            user = db.query(User).filter(User.id == token.id).first()
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="User does not exist"
                )

            # check user status, will raise error if user status is negative
            self.perform_user_check(user=user)
        except HTTPException as exc:
            return JsonResponseDict(
                message="Failed to validate user",
                error=exc.detail,
                status_code=exc.status_code,
            )
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
        db.refresh(user)

        return True

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
