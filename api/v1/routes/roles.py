# """Role routes module."""

# from fastapi import APIRouter, Depends, status, BackgroundTasks, HTTPException
# from sqlalchemy.orm import Session
# from typing import List
# from api.v1.models.user import User
# from api.v1.schemas.roles import (
#     SecondaryRoleCreate,
#     SecondaryRoleUpdate,
#     SecondaryRoleResponse,
#     RoleAssignmentRequest,
# )
# from api.v1.services.role_service import role_service
# from api.v1.services import user_service, audit_log_service
# from db.database import get_db
# from api.utils.json_response import JsonResponseDict

# roles_router = APIRouter(prefix="/roles", tags=["Roles"])


# @roles_router.post(
#     "/secondary",
#     response_model=SecondaryRoleResponse,
#     status_code=status.HTTP_201_CREATED,
#     summary="Create new secondary role",
# )
# async def create_secondary_role(
#     data: SecondaryRoleCreate,
#     bgt: BackgroundTasks,
#     db: Session = Depends(get_db),
#     user: User = Depends(user_service.get_current_superadmin),
# ):
#     """Create a new secondary role with custom permissions"""
#     role = await role_service.create_secondary_role(db, data, user.id)

#     # Log the action
#     bgt.add_task(
#         audit_log_service.log_action,
#         db,
#         user.id,
#         "secondary_role_create",
#         f"Created secondary role: {role.name}",
#     )

#     return role


# @roles_router.put(
#     "/secondary/{role_id}",
#     response_model=SecondaryRoleResponse,
#     status_code=status.HTTP_200_OK,
#     summary="Update secondary role",
# )
# async def update_secondary_role(
#     role_id: int,
#     data: SecondaryRoleUpdate,
#     bgt: BackgroundTasks,
#     db: Session = Depends(get_db),
#     user: User = Depends(user_service.get_current_superadmin),
# ):
#     """Update an existing secondary role"""
#     role = await role_service.update_secondary_role(db, role_id, data)

#     # Log the action
#     bgt.add_task(
#         audit_log_service.log_action,
#         db,
#         user.id,
#         "secondary_role_update",
#         f"Updated secondary role: {role.name}",
#     )

#     return role


# @roles_router.post(
#     "/assign/{user_id}",
#     status_code=status.HTTP_200_OK,
#     summary="Assign secondary role to user",
# )
# async def assign_secondary_role(
#     user_id: int,
#     data: RoleAssignmentRequest,
#     bgt: BackgroundTasks,
#     db: Session = Depends(get_db),
#     admin: User = Depends(user_service.get_current_user),
# ):
#     """Assign secondary role(s) to a user"""

#     if not any([admin.is_superadmin, admin.is_moderator]):
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED, detail="Not enough permissions."
#         )

#     assignments = await role_service.assign_role_to_user(
#         db, user_id, data.role_ids, admin.id, data.expires_at
#     )

#     # Log the action
#     bgt.add_task(
#         audit_log_service.log_action,
#         db,
#         admin.id,
#         "secondary_role_assign",
#         f"Assigned roles {data.role_ids} to user {user_id}",
#     )

#     return JsonResponseDict(
#         message="Roles assigned successfully",
#         data={
#             "assignments": [
#                 {"role_id": a.role_id, "expires_at": a.expires_at} for a in assignments
#             ]
#         },
#     )


# @roles_router.delete(
#     "/revoke/{user_id}/{role_id}",
#     status_code=status.HTTP_200_OK,
#     summary="Revoke secondary role from user",
# )
# async def revoke_secondary_role(
#     user_id: int,
#     role_id: int,
#     bgt: BackgroundTasks,
#     db: Session = Depends(get_db),
#     admin: User = Depends(user_service.get_current_user),
# ):
#     """Revoke a secondary role from a user"""

#     if not any([admin.is_superadmin, admin.is_moderator]):
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED, detail="Not enough permissions."
#         )

#     await role_service.revoke_role_from_user(db, user_id, role_id)

#     # Log the action
#     bgt.add_task(
#         audit_log_service.log_action,
#         db,
#         admin.id,
#         "secondary_role_revoke",
#         f"Revoked role {role_id} from user {user_id}",
#     )

#     return JsonResponseDict(message="Role revoked successfully")


# @roles_router.get(
#     "/secondary",
#     response_model=List[SecondaryRoleResponse],
#     status_code=status.HTTP_200_OK,
#     summary="List all secondary roles",
# )
# async def list_secondary_roles(
#     db: Session = Depends(get_db),
#     admin: User = Depends(user_service.get_current_user),
# ):
#     """List all available secondary roles"""

#     if not any([admin.is_superadmin, admin.is_moderator]):
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED, detail="Not enough permissions."
#         )

#     roles = await role_service.list_all_roles(db)
#     return roles


# @roles_router.get(
#     "/user/{user_id}",
#     response_model=List[SecondaryRoleResponse],
#     status_code=status.HTTP_200_OK,
#     summary="Get user's secondary roles",
# )
# async def get_user_secondary_roles(
#     user_id: int,
#     db: Session = Depends(get_db),
#     admin: User = Depends(user_service.get_current_user),
# ):
#     """Get all secondary roles assigned to a user"""
#     roles = await role_service.get_user_roles(db, user_id)
#     return roles
