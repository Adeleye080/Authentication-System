from api.v1.models.base_model import BaseModel
from sqlalchemy import Column, String, Index, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime, timezone


class CountryBlacklist(BaseModel):
    """Tracks blacklisted countries."""

    __tablename__ = "auth_country_blacklists"

    country_code = Column(String(2), unique=True, nullable=False)
    country_name = Column(String(128), nullable=False)
    reason = Column(String(256), nullable=False)

    __table_args__ = (
        Index("ix_blacklisted_country_code", "country_code"),
        Index("ix_blacklisted_country_name", "country_name"),
        Index("ix_blacklisted_country_reason_for_being_blacklisted", "reason"),
    )


class CountryBlacklistHistory(BaseModel):
    """Tracks changes to the blacklist."""

    __tablename__ = "auth_country_blacklist_history"

    country_code = Column(String(2), unique=False, nullable=False)
    country_name = Column(String(128), nullable=False)
    reason = Column(String(256), nullable=True)
    action = Column(String(64), nullable=False)  # e.g., "added", "removed", "updated"
    # User or system making the change
    changed_by = Column(String(128), nullable=True)
    timestamp = Column(
        DateTime(timezone=True), default=datetime.now(timezone.utc), nullable=False
    )

    __table_args__ = (
        Index("ix_blacklist_history_country_code", "country_code"),
        Index("ix_blacklist_history_country_name", "country_name"),
        Index("ix_blacklist_history_country_reason_for_being_blacklisted", "reason"),
        Index("ix_blacklist_history_action", "action"),
        Index("ix_blacklist_record_changed_by", "changed_by"),
        Index("ix_blacklist_history_timestamp", "timestamp"),
    )


# NOT USING FOREIGN KEY RELATIONSHIP TO AVOID COMPLEXITIES IN DATABASE
