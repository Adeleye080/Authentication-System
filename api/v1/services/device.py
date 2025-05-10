"""
User Device Service Module
Handles all user device related operations in the database
"""

from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from api.v1.models.device import Device
from api.v1.models.user import User
from typing import Dict


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
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="No devices found!"
            )
        return devices

    def get(self, db: Session, device_id: str):
        """
        Get a device by its id
        """
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User device not found!"
            )
        return device

    def get_by_user_id(self, db: Session, user_id: str):
        """
        Get all devices of a user by user id
        """
        devices = db.query(Device).filter(Device.user_id == user_id).all()
        if len(devices) == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User has no devices registered!",
            )
        return devices

    def create(self, db: Session, device_info: Dict, owner: User):
        """
        Create a new device
        """
        from api.utils.user_device_agent import generate_device_fingerprint

        device_fingerprint = generate_device_fingerprint(device_info.get("user_agent"))
        device_exists = (
            db.query(Device)
            .filter(
                Device.user_id == owner.id,
                Device.device_fingerprint == device_fingerprint,
            )
            .first()
        )
        if device_exists:
            return

        device_info.update(
            {"user_id": owner.id, "device_fingerprint": device_fingerprint}
        )

        # purify device info dict for Device object argument
        device_info.pop("ip_address") if device_info["ip_address"] else None
        (
            device_info.pop("is_email_client")
            if "is_email_client" in device_info.keys()
            else None
        )
        device_info["user_agent_string"] = device_info.pop("user_agent")

        device = Device(**device_info)
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
