"""
MMDB model for GeoIP database
This model is used to track the MMDB update process and the last update time.
"""

from api.v1.models.base_model import BaseModel
from db.database import get_db
from datetime import datetime, timezone, timedelta
from typing import List


class MMDB_TRACKER(BaseModel):
    """
    Simple MMDB model for GeoIP database tracking
    This model is used to track the MMDB update process and the last update time.

    Inherits `id`, `created_at` and `updated_at` from `BaseModel`.
    """

    __tablename__ = "auth_mmdb_tracker"
    __table_args__ = {"extend_existing": True}

    def update_tracker(self):
        """
        This function updates the update time in the mmdb tracker database.
        Ensuring efficient tracking of the mmdb database age
        """
        db_generator = get_db()
        db = next(db_generator)

        try:
            tracker_object: List[MMDB_TRACKER] = db.query(self).all()

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
        Returns: `True` if expired, `False` otherwise.
        """

        db_generator = get_db()
        db = next(db_generator)

        try:
            last_update_tracker: MMDB_TRACKER = db.query(self).first()
            track_time = last_update_tracker.updated_at + timedelta(days=5)
        finally:
            db_generator.close()

        if track_time > datetime.now(tz=timezone.utc):
            return False
        return True
