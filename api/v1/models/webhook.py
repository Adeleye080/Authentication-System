from sqlalchemy import Column, String, DateTime, func


class WebhoookURL:
    __tablename__ = "webhook_url"

    url = Column(String(200), nullable=False)
    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
