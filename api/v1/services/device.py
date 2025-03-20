"""
User Device Service Module
Handles all user device related operations in the database
"""

from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from api.v1.models.device import Device


class DevicesService:
    """
    User devices service
    """

    def fetch_all(self, db: Session):
        """
        Get all devices

        Should not be used except intentionally and for admin purposes
        """
        devices = db.query(Device).all()
        if len(devices) == 0:
            raise HTTPException(status_code=404, detail="No devices found!")
        return devices

    def get(self, db: Session, device_id: str):
        """
        Get a device by its id
        """
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise HTTPException(status_code=404, detail="User device not found!")
        return device

    def get_by_user_id(self, db: Session, user_id: str):
        """
        Get all devices of a user by user id
        """
        devices = db.query(Device).filter(Device.user_id == user_id).all()
        if len(devices) == 0:
            raise HTTPException(
                status_code=404, detail="User has no devices registered!"
            )
        return devices

    def create(self, db: Session, schema):
        """
        Create a new device
        """

        device_exists = (
            db.query(Device)
            .filter(
                Device.device_id == schema.device_id,
                Device.user_agent == schema.user_agent,
                Device.device_name == schema.device_name,
            )
            .first()
        )
        if device_exists:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Device already exists"
            )

        device = Device(**schema.model_dump())
        db.add(device)
        db.commit()
        db.refresh(device)
        return device

    def delete(self, db: Session, device_id):
        """
        Delete a device
        """
        db.delete(device_id)
        db.commit()
        return

    def delete_all_device_by_user_id(self, db: Session, user_id):
        """
        Delete all devices of a user
        """
        db.query(Device).filter(Device.user_id == user_id).delete()
        db.commit()
        return
