"""Role services module."""

from typing import List, Optional, Tuple
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from fastapi import HTTPException, status
from api.v1.models.roles import SecondaryRole
from api.v1.models.user import User
from api.v1.schemas.roles import SecondaryRoleCreate, SecondaryRoleUpdate


class RoleService:
    """Role service class"""

    async def get_all_roles(self, db: Session) -> List[SecondaryRole]:
        """Fetch all secondary roles"""

        return db.query(SecondaryRole).all()

    async def get_role_by_id(
        self, db: Session, role_id: int
    ) -> Optional[SecondaryRole]:
        """Get a secondary role by ID"""
        role = db.query(SecondaryRole).filter(SecondaryRole.id == role_id).first()
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Secondary role with ID {role_id} not found",
            )
        return role

    async def create_secondary_role(
        self, db: Session, data: SecondaryRoleCreate, creator_id: str
    ) -> SecondaryRole:
        """Create a new secondary role"""
        try:
            role = SecondaryRole(
                name=data.name,
                description=data.description,
                created_by=creator_id,
            )
            db.add(role)
            db.commit()
            return role
        except IntegrityError:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Role with name '{data.name}' already exists",
            )
        except Exception as e:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred while creating the role",
            ) from e

    async def update_secondary_role(
        self, db: Session, role_id: str, data: SecondaryRoleUpdate, updater_id: str
    ) -> SecondaryRole:
        """Update an existing secondary role"""
        role = await self.get_role_by_id(db, role_id)

        if data.name:
            role.name = data.name
        if data.description:
            role.description = data.description
        # audit log the reason for update
        # audit_log_service.log_role_update(role_id=role_id, updater_id=updater_id, reason=data.reason, former_role_data=role)

        try:
            db.commit()
            return role
        except IntegrityError:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Role with name '{data.name}' already exists",
            )
        except Exception as e:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred while updating the role",
            ) from e

    async def assign_role_to_user(
        self,
        db: Session,
        user_id: int,
        role_ids: List[int],
        assigner: User,
    ) -> User:
        """Assign secondary roles to a user"""
        from api.v1.services import user_service

        assignee = user_service.fetch_by_id(db, user_id)
        if assignee.is_superadmin and not assigner.is_superadmin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to assign roles to this user",
            )

        roles_to_link = (
            db.query(SecondaryRole).filter(SecondaryRole.id.in_(role_ids)).all()
        )
        if not roles_to_link or len(roles_to_link) != len(role_ids):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="One or more roles not found",
            )

        for role in roles_to_link:
            if role not in assignee.secondary_roles:
                assignee.secondary_roles.append(role)

        db.commit()

        return assignee

        # log to audit logs, indicate assigner.

    async def revoke_role_from_user(
        self, db: Session, user_id: str, role_id: str, revoker: User
    ) -> User:
        """Revoke a secondary role from a user"""
        from api.v1.services import user_service

        assignee = user_service.fetch_by_id(db, user_id)
        if assignee.is_superadmin and not revoker.is_superadmin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to revoke roles for this user",
            )

        role = await self.get_role_by_id(db, role_id)

        if role in assignee.secondary_roles:
            try:
                assignee.secondary_roles.remove(role)
                db.commit()
                return assignee
            except Exception as e:
                db.rollback()
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="An error occurred when revoking role. please try again",
                ) from e
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found for user",
            )

    async def fetch_roles_assigned_to_user(
        self, db: Session, user_id: str, request_user: User
    ) -> Tuple[User, List[SecondaryRole]]:
        """
        Fetch roles belonging to a user

        Args:
            :param db: Database session
            :param user_id: ID of the user whose roles are to be fetched
            :param request_user: The user making the request (for permission checks)
        """
        from api.v1.services import user_service

        user = user_service.fetch_by_id(db, user_id)
        if user.is_superadmin and not request_user.is_superadmin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to view roles for this user",
            )
        return user, user.secondary_roles

    async def delete_role(
        self, db: Session, role_id: int, action_by: User
    ) -> Tuple[str, str]:
        """
        Delete a secondary role\n
        Returns tuple `(role_name, role_id)
        """

        role = await self.get_role_by_id(db, role_id)
        role_name, role_id = role.name, role.id

        try:
            db.delete(role)
            db.commit()
        except Exception as e:
            db.rollback()
            raise HTTPException(
                detail="An error occurred while deleting role. please try again.",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            ) from e

        return role_name, role_id
