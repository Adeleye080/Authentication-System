from fastapi import HTTPException, status
from api.v1.models.attributes import Attributes, UserAttribute, AttributeValues
from api.v1.models.user import User
from api.v1.schemas.attributes import UserAttributeCreate
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from typing import List


class AttributeService:
    """Attribute service class"""

    async def get_attr_by_id(self, db: Session, attr_id: str) -> Attributes:
        """Fetch attribute by ID"""

        attr = db.query(Attributes).filter(Attributes.id == attr_id).first()

        if not attr:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Attribute with ID {attr_id} not found",
            )

        return attr

    async def create_new(self, db: Session, schema: UserAttributeCreate) -> Attributes:
        """Create new attribute category"""

        try:
            new_attr = Attributes(name=schema.name)
            db.add(new_attr)
            db.flush()

            if len(schema.allowed_values) > 0:
                values = [
                    AttributeValues(attribute_id=new_attr.id, value=attr)
                    for attr in schema.allowed_values
                ]
                db.add_all(values)
            db.commit()

            return new_attr
        except IntegrityError:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"attribute with name '{schema.name}' already exists",
            )
        except Exception as e:
            db.rollback()
            print(e)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred while creating the role",
            ) from e

    async def assign_attributes_to_user(
        self, db: Session, user_id: str, attrs_ass: List[tuple], assigner: User
    ):
        """Assigns an attribute to a user"""
        from api.v1.services import user_service

        assignee = user_service.fetch_by_id(db=db, id=user_id)

        if assignee.is_superadmin and not assigner.is_superadmin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to assign roles to this user",
            )

        # get the attributes id
        attrs_name_ids = [a[0] for a in attrs_ass]
        attrs_value_ids = [a[1] for a in attrs_ass]

        attrs_to_assign = (
            db.query(Attributes).filter(Attributes.id.in_(attrs_name_ids)).all()
        )
        values_to_assign = (
            db.query(AttributeValues)
            .filter(AttributeValues.id.in_(attrs_value_ids))
            .all()
        )

        exc = HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="One or more attributes not found",
        )
        if not attrs_to_assign or len(attrs_to_assign) != len(attrs_name_ids):
            raise exc
        if not values_to_assign or len(values_to_assign) != len(attrs_value_ids):
            raise exc

        association = [
            UserAttribute(
                user_id=assignee.id,
                attribute_id=a_id_as[0],
                attribute_value_id=a_id_as[1],
            )
            for a_id_as in attrs_ass
        ]

        # for attr in attrs_to_assign:
        #     if attr not in assignee.attributes:
        #         assignee.attributes.append(attr)

        db.add_all(association)
        db.commit()

        return assignee

    async def revoke_attributes_from_user(
        self, db: Session, user_id: str, role_id: str, revoker: User
    ) -> User:
        """Revoke attributes from a user"""
        from api.v1.services import user_service

        assignee = user_service.fetch_by_id(db, user_id)
        if assignee.is_superadmin and not revoker.is_superadmin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to revoke attribute for this user",
            )

        role = await self.get_attr_by_id(db, role_id)

        if role in assignee.attributes:
            try:
                assignee.attributes.remove(role)
                db.commit()
                return assignee
            except Exception as e:
                db.rollback()
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="An error occurred when removing attribute. please try again",
                ) from e
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="attribute not found for this user",
            )
