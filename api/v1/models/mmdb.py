"""
MMDB model for GeoIP database
This model is used to track the MMDB update process and the last update time.
"""

from api.v1.models.base_model import BaseModel
from db.database import get_db
from datetime import datetime, timezone, timedelta
from typing import List
from sqlalchemy import func


class MMDB_TRACKER(BaseModel):
    """
    Simple MMDB model for GeoIP database tracking
    This model is used to track the MMDB update process and the last update time.

    Inherits `id`, `created_at` and `updated_at` from `BaseModel`.
    """

    __tablename__ = "auth_mmdb_tracker"
    __table_args__ = {"extend_existing": True}

    def __init__(self):
        """create tracker if it doesn't exist"""
        db_generator = get_db()
        db = next(db_generator)

        try:
            if db.query(func.count(MMDB_TRACKER.id)).scalar() == 0:
                db.add(self)
                db.commit()
        finally:
            db_generator.close()

    def update_tracker(self):
        """
        This function updates the update time in the mmdb tracker database.
        Ensuring efficient tracking of the mmdb database age
        """
        db_generator = get_db()
        db = next(db_generator)

        try:
            tracker_object: List[MMDB_TRACKER] = db.query(MMDB_TRACKER).all()

            if tracker_object:

                if len(tracker_object) > 1:
                    # clean up, there should not be multiple mmdb tracker
                    pass
                else:
                    tracker_object = tracker_object[0]

                tracker_object.updated_at = datetime.now(tz=timezone.utc)
                db.add(tracker_object)
                db.commit()
            else:
                db.add(self)
                db.commit()

        finally:
            db_generator.close()

    def last_update_expired(self) -> bool:
        """
        checks if the last mmdb update is expired
        The system considers mmdb age of 5 or more days expired.
        they remain in use until updates are made.
        Returns: `True` if expired or if no tracker exist, `False` otherwise.
        """

        db_generator = get_db()
        db = next(db_generator)

        try:
            last_update_tracker: MMDB_TRACKER = db.query(MMDB_TRACKER).first()
            if not last_update_tracker:
                return True
            track_time = last_update_tracker.updated_at + timedelta(days=5)
            dialect = db.bind.dialect.name
        finally:
            db_generator.close()

        if dialect == "postgresql":
            now = datetime.now(tz=timezone.utc)
        else:
            now = datetime.now()

        if track_time > now:
            return False
        return True
