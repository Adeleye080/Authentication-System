from sqlalchemy import Integer, Column, String, ForeignKey, DateTime, func, Enum
from api.v1.models.base_model import Base
from api.v1.schemas.user import BanHistoryStatusEnum


class AccountBanHistory(Base):
    """ """

    __tablename__ = "auth_account_ban_history"

    id = Column(Integer, nullable=False, autoincrement=True, primary_key=True)
    status = Column(Enum(BanHistoryStatusEnum), nullable=False)
    # bans is serious issue, so reason cannot be null
    reason = Column(String(256), nullable=False)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=True
    )
