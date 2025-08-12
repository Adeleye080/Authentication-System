from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from pydantic import EmailStr


def check_model_existence(db: Session, model, id: str = None):
    """Checks if a model exists by its id or any other optional attribute"""

    if id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="No ID given"
        )

    if id:
        obj = db.get(model, ident=id)

    if not obj:
        raise HTTPException(status_code=404, detail=f"{model.__name__} does not exist")

    return obj


def is_email(email: str):
    """Checks if a string is a valid email format"""

    try:
        EmailStr._validate(email)
        return True
    except ValueError:
        return False


def is_uuid(value: str) -> bool:
    """Checks if a string is a valid UUID format"""

    try:
        from uuid import UUID

        UUID(value, version=4)
        return True
    except ValueError:
        return False
