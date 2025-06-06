from fastapi import HTTPException, Depends, Request, status, Security
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext  # type: ignore
from typing import Tuple, Optional, List
from pydantic import EmailStr
from sqlalchemy.orm import Session
import datetime as dt
from jose import JWTError, jwt, ExpiredSignatureError  # type: ignore
from sqlalchemy import func
from db.database import get_db

from api.utils.settings import settings
from api.v1.models.user import User
from api.v1.models.refresh_token import RefreshToken
from api.v1.schemas.audit_logs import (
    AuditLogCreate,
    AuditLogEventEnum,
    AuditLogStatuses,
)
from api.v1.schemas.user import (
    UserCreate,
    AccessTokenData,
    DeactivateUserSchema,
    UserUpdateSchema,
    LoginSource,
)
from api.core.base.services import Service
from api.utils.encrypters_and_decrypters import base64, cipher_suite
import logging


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/swagger-login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
logger = logging.getLogger(__name__)


class UserService(Service):
    """Auth user service"""

    def create(self, db: Session, schema: UserCreate):
        """Creates a Auth new user"""

        if db.query(User).filter(User.email == schema.email).first():
            raise HTTPException(
                status_code=409,
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
            # log error
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

    def fetch_by_id(self, db: Session, id: str) -> User:
        """fetch a single user from the system"""

        # user = db.query(User).filter(User.id == id).first()
        user = db.get(entity=User, ident=id)
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

    def update(
        self,
        db: Session,
        schema: UserUpdateSchema,
        user_id: str = None,
        user_obj: User = None,
    ) -> User:
        """Update an Auth user data. must supply user_id or user_obj

        Args:
            db (Session): Database session.
            user_id (str): ID of the user to update.
            user_obj (User): User Object
            schema (UserUpdateSchema): Pydantic schema containing fields to update.

        Returns:
            User: The updated user object.
        """

        if not any([user_id, user_obj]):
            raise ValueError("User ID or User Object must be given")

        if user_obj:
            user = user_obj
        elif user_id:
            # Find the user by ID
            user = db.query(User).filter(User.id == user_id).first()
            if not user:
                raise HTTPException(status_code=404, detail="User not found")

        # Convert the schema to a dictionary (excluding unset fields)
        update_data = schema.model_dump(exclude_unset=True)

        # Update the user fields
        for key, value in update_data.items():
            if key == "recovery_email":
                if value == user.email:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="User email and recovery email cannot be the same.",
                    )

            if key == "email":
                if value == user.email:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Old and new email cannot be the same",
                    )
            setattr(user, key, value)

        db.commit()
        db.refresh(user)

        return user

    def delete(self, db: Session, user_id: str) -> User:
        """
        deletes an auth user from the system
        """

        user = self.fetch_by_id(db=db, id=user_id)

        if user.is_deleted is True:
            raise HTTPException(
                detail="Forbidden, User has been previously deleted!", status_code=403
            )

        try:
            setattr(user, "is_deleted", True)
            setattr(user, "is_active", False)
            self.deactivate_user
            db.commit()
            db.refresh(user)
        except Exception as exc:
            raise HTTPException(
                status_code=500, detail="Database operation to delete user failed"
            )

        return user

    def hard_delete_user(self, db: Session, user_id: str) -> User:
        """
        Remove user totally from the system.\n
        retains no user record
        """

        user = self.fetch_by_id(db=db, id=user_id)

        db.delete(user)
        db.commit()

        return user

    def authenticate_user(self, db: Session, email: str, password: str) -> User:
        """Function to authenticate a user with password"""

        user = db.query(User).filter(User.email == email).first()

        if not user:
            raise HTTPException(status_code=404, detail="User does not exist")

        self.perform_user_check(user)

        if not self.verify_password(password, user.password):
            raise HTTPException(status_code=400, detail="Invalid user credentials")

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

    def perform_user_check(self, user: User) -> True:
        """
        This checks if a user is active and verified and not a deleted or banned user.\n
        It raises an HTTPException if any of the checks fail.\n
        This is important for security purposes and to ensure that the user
        is allowed to perform actions that require authentication.\n

        :param user: User: User object
        :return: bool: True if all checks pass
        :raises HTTPException: if any of the checks fail
        """

        if not user.is_verified:
            raise HTTPException(
                detail="User is not verified", status_code=status.HTTP_401_UNAUTHORIZED
            )
        if user.is_deleted:
            from api.v1.services import audit_log_service

            audit_log_service.log_without_bgt(
                schema=AuditLogCreate(
                    user_id=user.id,
                    event=AuditLogEventEnum.LOGIN,
                    description="Deleted user attempted login",
                    status=AuditLogStatuses.FAILED,
                    ip_address="Not Captured",
                    user_agent="Not Captured",
                )
            )
            raise HTTPException(
                detail="User does not exist",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        if not user.is_active:
            raise HTTPException(
                detail="User is inactive/deactivated",
                status_code=status.HTTP_403_FORBIDDEN,
            )

        if user.is_banned:
            raise HTTPException(
                detail="User has banned from using this service",
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

    def create_access_token(self, db: Session, user_obj: User) -> str:
        """Function to create access token"""

        try:
            secondary_role = user_obj.secondary_role
            user_id = user_obj.id

            # define user role
            user_role = "user"
            if user_obj.is_superadmin:
                user_role = "superadmin"
            elif user_obj.is_moderator:
                user_role = "moderator"

            expires = dt.datetime.now(dt.timezone.utc) + dt.timedelta(
                minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
            )
            data = {
                "sub": user_id,
                "exp": expires,
                "type": "access",
                "primary_role": user_role,
                "secondary_role": secondary_role,
            }

            attributes = self.get_user_attributes(db=db, user_obj=user_obj)
            if attributes:
                data["attributes"] = attributes

            encoded_jwt = jwt.encode(data, settings.SECRET_KEY, settings.ALGORITHM)
        except Exception as exc:
            print(exc)
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

    def _batch_delete_refresh_tokens(self, db: Session, user_id: str) -> None:
        """Function to delete all refresh tokens for a user"""

        try:
            db.query(RefreshToken).filter(RefreshToken.user_id == user_id).delete()
            db.commit()
        except Exception as exc:
            raise HTTPException(
                status_code=500, detail="Failed to delete refresh tokens"
            ) from exc
        return None

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

    def verify_and_revoke_refresh_token(
        self, db: Session, refresh_token: str, credentials_exception
    ) -> AccessTokenData:
        """
        Funtcion to decode and verify refresh token.
        Also automatically revokes the token since refresh tokens are single use
        and should be rotated after use.
        """

        refresh_token_obj = None

        try:

            # Decode the refresh token
            payload = jwt.decode(
                refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
            )
            user_id = payload.get("sub")
            token_type = payload.get("type")

            if user_id is None:
                raise credentials_exception

            if token_type == "access":
                raise HTTPException(detail="Access token not allowed", status_code=400)

            refresh_token_obj = (
                db.query(RefreshToken)
                .filter(
                    RefreshToken.user_id == user_id,
                    RefreshToken.token == refresh_token,
                )
                .first()
            )

            if not refresh_token_obj:
                raise HTTPException(status_code=400, detail="Untracked token")
            if refresh_token_obj.revoked:
                raise HTTPException(status_code=400, detail="Token has been revoked")

            token_data = AccessTokenData(id=user_id)

        except ExpiredSignatureError as exc:
            raise credentials_exception from exc

        except JWTError as exc:
            raise HTTPException(
                status_code=400, detail="Invalid token, please input a valid token"
            ) from exc

        except Exception as exc:

            if hasattr(exc, "detail"):
                raise HTTPException(
                    status_code=exc.status_code, detail=exc.detail
                ) from exc
            raise HTTPException(
                status_code=400, detail="Invalid token, please input a valid token"
            ) from exc

        finally:
            if refresh_token_obj:
                refresh_token_obj.revoked = True
                db.add(refresh_token_obj)
                db.commit()
                db.refresh(refresh_token_obj)

        return token_data

    def revoke_refresh_token(self, db: Session, token: str) -> None:
        """Function to revoke refresh token"""

        if not token:
            raise HTTPException(status_code=400, detail="No token provided")

        try:
            payload = jwt.decode(
                token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
            )
            owner_id = payload.get("sub")
            token_type = payload.get("type")

            if owner_id is None:
                raise HTTPException(400, "Invalid token")
            if token_type == "access" or token_type is None:
                raise HTTPException(400, "Invalid token")
        except ExpiredSignatureError:
            raise HTTPException(400, "Token expired")

        except JWTError as exc:
            raise HTTPException(400, "Invalid token") from exc

        refresh_token = (
            db.query(RefreshToken)
            .filter(
                RefreshToken.user_id == owner_id,
                RefreshToken.token == token,
            )
            .first()
        )

        if not refresh_token:
            raise HTTPException(400, "Invalid token")
        if refresh_token.revoked:
            raise HTTPException(400, "Token has been revoked")

        refresh_token.revoked = True
        db.add(refresh_token)
        db.commit()

    def refresh_access_token(
        self, db: Session, current_refresh_token: str
    ) -> Tuple[str, str]:
        """
        Function to generate new access token and rotate refresh token.
        Revokes current refresh token
        """

        credentials_exception = HTTPException(
            status_code=401, detail="Refresh token expired"
        )

        # Verify and revoke the refresh token
        # This will also check if the token is expired and raise an exception
        token = self.verify_and_revoke_refresh_token(
            db, current_refresh_token, credentials_exception
        )

        if token:

            # check the token owner status e.g. active, deleted, verified
            owner = self.fetch_by_id(db=db, id=token.id)
            self.perform_user_check(user=owner)

            access = self.create_access_token(user_id=token.id)
            refresh = self.create_refresh_token(db=db, user_id=token.id)

            return (access, refresh)

    def get_user_object_using_refresh_token(
        self, refresh_token: str, db: Session
    ) -> User | None:
        """decode and return token owner object"""

        credentials_exception = HTTPException(
            status_code=401,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

        try:

            # Decode the refresh token
            payload = jwt.decode(
                refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
            )
            user_id = payload.get("sub")
            token_type = payload.get("type")

            if user_id is None:
                raise credentials_exception

            if token_type != "refresh":
                raise credentials_exception

            owner = self.fetch_by_id(db=db, id=user_id)

        except ExpiredSignatureError:
            logger.critical(
                f"Detected jwt refresh token with unrecognized signature. Token: {refresh_token}",
                exc_info=1,
            )
            raise credentials_exception

        except Exception as exc:
            raise credentials_exception

        return owner

    def get_current_user(
        self, access_token: str = Security(oauth2_scheme), db: Session = Depends(get_db)
    ) -> User:
        """
        Dependency to get current logged in user.

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
            raise exc
        return user

    def get_current_superadmin(
        self, access_token: str = Security(oauth2_scheme), db: Session = Depends(get_db)
    ):
        """Dependency to get current superadmin user"""
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
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Auth user does not exist",
                )

            # check user status, will raise error if user status is negative
            self.perform_user_check(user=user)
            if not user.is_superadmin:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="You do not have permission to perform this action",
                )
        except HTTPException as exc:
            raise exc
        return user

    def get_current_moderator(
        self, access_token: str = Security(oauth2_scheme), db: Session = Depends(get_db)
    ):
        """Dependency to get current moderator user"""
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

            if not user.is_moderator:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not enough permission.",
                )
        except HTTPException as exc:
            raise exc
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
        mode: str = "change",
        old_password: Optional[str] = None,
    ) -> Tuple[str, str]:
        """
        Method to change the user's password.\n
        Mechanism: This process invalidates all existing refresh tokens
        ensuring only current session remain alive.

        :param new_password: str: New password
        :param user: User: User object
        :param db: Session: Database session
        :param mode: str: Mode of password change (default: "change", acceptable modes are "change" and "reset")
        :param old_password: Optional[str]: Old password (if provided)
        :return: Tuple[str, str]: New access and refresh tokens
        """

        if mode not in ["change", "reset"]:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Unable to change/reset password",
            )
        if old_password == new_password:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Old Password and New Password cannot be the same",
            )
        if old_password is None:
            if user.password is None or mode == "reset":
                user.password = self.hash_password(new_password)
                db.commit()
            else:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="Old Password must not be empty.",
                )
        elif not self.verify_password(old_password, user.password):
            raise HTTPException(status_code=400, detail="Incorrect old password")
        else:
            user.password = self.hash_password(new_password)
            db.commit()

        # Revoke all old refresh tokens
        self._batch_delete_refresh_tokens(db=db, user_id=user.id)

        # create new credentials
        new_access_token = self.create_access_token(user_id=user.id)
        new_refresh_token = self.create_refresh_token(db=db, user_id=user.id)

        return (
            new_access_token,
            new_refresh_token,
        )

    def create_and_encrypt_temp_login_token(
        self, user_id: str, ip_address: str, validity: int = 10
    ) -> str:
        """
        Generate and encrypt temporary login token.\n
        Helps in tracking user login attempt source and IP.
        """
        expire = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=validity)
        to_encode = {
            "sub": user_id,
            "exp": expire,
            "2fa_pending": True,
            "ip": ip_address,
        }
        encoded_token = jwt.encode(
            to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
        )

        encrypted_token = cipher_suite.encrypt(encoded_token.encode())
        encoded_encrypted_token = base64.urlsafe_b64encode(encrypted_token).decode()

        return encoded_encrypted_token

    def decrypt_and_validate_temp_login_token(self, token: str, current_ip: str) -> str:
        """
        Decrypt and validate temporary login token. \n
        Return owner ID if valid, raise HTTPException otherwise
        """
        try:
            decoded_encrypted_token = base64.urlsafe_b64decode(token)
            payload = cipher_suite.decrypt(decoded_encrypted_token).decode()

            payload = jwt.decode(
                payload, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
            )
            if not payload.get("2fa_pending"):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="Not a 2FA token"
                )

            if payload.get("ip") != current_ip:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="IP mismatch! You're not the initiator of this login.",
                )

            return payload.get("sub", None)
        except ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Token has expired, Please restart login process.",
            )
        except JWTError as e:

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Invalid temporary login token: {e}",
            )

        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=exc
            )

    def get_user_attributes(
        self, db: Session, user_obj: User = None, user_id: str = None
    ) -> dict:
        """Convert auth user attributes to a dictionary. expects user object or user ID"""

        if not any([user_obj, user_id]):
            raise ValueError("User ID or User Object must be given")
        if user_obj:
            attributes = {attr.key: attr.value for attr in user_obj.attributes}
        elif user_id:
            user = db.query(User).filter(User.id == user_id).first()
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Auth user does not exist",
                )
            attributes = {attr.key: attr.value for attr in user.attributes}

        if not attributes:
            return {}
        return attributes
