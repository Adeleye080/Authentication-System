#!/usr/bin/env python3
"""
This is the Base Model Class
"""
from uuid_extensions import uuid7
from fastapi import Depends
from db.database import Base
from sqlalchemy import Column, String, DateTime, func, Index


class BaseModel(Base):
    """This model creates helper methods for all models"""

    __abstract__ = True

    id = Column(String(36), primary_key=True, index=True, default=lambda: str(uuid7()))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    @classmethod
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if not cls.__abstract__:
            cls.__table_args__ = getattr(cls, "__table_args__", ()) + (
                Index(f"ix_{cls.__tablename__}_id", "id"),
            )

    def to_dict(self):
        """returns a dictionary representation of the instance"""

        obj_dict = self.__dict__.copy()
        if obj_dict["_sa_instance_state"]:
            del obj_dict["_sa_instance_state"]
        if self.created_at:
            obj_dict["created_at"] = self.created_at.isoformat()
        if self.updated_at:
            obj_dict["updated_at"] = self.updated_at.isoformat()
        return obj_dict

    @classmethod
    def get_all(cls):
        from db.database import get_db

        db = Depends(get_db)
        """ returns all instance of the class in the db
        """
        return db.query(cls).all()

    @classmethod
    def get_by_id(cls, id):
        from db.database import get_db

        db = Depends(get_db)
        """ returns a single object from the db
        """
        obj = db.query(cls).filter_by(id=id).first()
        return obj
