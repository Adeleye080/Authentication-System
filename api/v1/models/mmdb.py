"""
MMDB model for GeoIP database
This model is used to track the MMDB update process and the last update time.
"""

from api.v1.models.base_model import BaseModel


class MMDB_TRACKER(BaseModel):
    """
    Simple MMDB model for GeoIP database tracking
    This model is used to track the MMDB update process and the last update time.

    Inherits `id`, `created_at` and `updated_at` from `BaseModel`.
    update id on every update to the mmdb, resulting in update to the `updated_at` field
    """

    __tablename__ = "auth_mmdb_tracker"
    __table_args__ = {"extend_existing": True}
