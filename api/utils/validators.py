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
