from apscheduler.schedulers.asyncio import AsyncIOScheduler  # type: ignore
from sqlalchemy.exc import SQLAlchemyError
import logging
from datetime import datetime, timezone
from db.database import get_db


scheduler = AsyncIOScheduler()
logger = logging.getLogger(__name__)


async def delete_revoked_and_expired_refresh_token():
    """
    Asynchronously delete revoked and expired refresh tokens in batches
    """
    from api.v1.models.refresh_token import RefreshToken

    db_generator = get_db()
    db = next(db_generator)

    try:
        # Calculate current time
        expiration_time = datetime.now(timezone.utc)
        batch_size = 1000

        # Delete expired refresh tokens in batches
        expired_count = 0
        while True:
            expired_tokens = (
                db.query(RefreshToken)
                .filter(RefreshToken.expires_at < expiration_time)
                .limit(batch_size)
                .all()
            )
            if not expired_tokens:
                break  # Exit when no more tokens to delete

            for token in expired_tokens:
                db.delete(token)
            db.commit()
            expired_count += len(expired_tokens)

        # Delete revoked refresh tokens in batches
        revoked_count = 0
        while True:
            revoked_tokens = (
                db.query(RefreshToken)
                .filter(RefreshToken.revoked == True)
                .limit(batch_size)
                .all()
            )
            if not revoked_tokens:
                break  # Exit when no more tokens to delete

            for token in revoked_tokens:
                db.delete(token)
            db.commit()
            revoked_count += len(revoked_tokens)

        # Log the results
        logger.info(
            f"Deleted {expired_count} expired tokens and {revoked_count} revoked tokens."
        )
    except SQLAlchemyError as e:
        logger.error(f"Error deleting tokens: {e}")
        db.rollback()
    finally:
        db.close()


# Schedule the job to run every hour
scheduler.add_job(delete_revoked_and_expired_refresh_token, "interval", minutes=1)
