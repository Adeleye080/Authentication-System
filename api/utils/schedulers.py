"""Scheduler for background tasks.
This module uses APScheduler to schedule tasks such as downloading and updating the MaxMind GeoLite2 database,
deleting expired and revoked refresh tokens, and deleting expired audit logs.
"""

from apscheduler.schedulers.background import BackgroundScheduler  # type: ignore
from apscheduler.executors.pool import ThreadPoolExecutor, ProcessPoolExecutor  # type: ignore
from sqlalchemy.exc import SQLAlchemyError
import logging
from datetime import datetime, timezone, timedelta
from db.database import get_db
import os
import requests
import shutil
from api.utils.settings import settings
from api.v1.models.mmdb import MMDB_TRACKER
from api.v1.models.audit_logs import AuditLog


executors = {
    "default": ThreadPoolExecutor(5),
    "processpool": ProcessPoolExecutor(2),
}

scheduler = BackgroundScheduler(executors=executors)
# Set the timezone to UTC
scheduler.configure(timezone=timezone.utc)

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


def download_and_update_geolite_db():
    """
    Download and extract the latest MaxMind GeoLite2 City database.
    """

    # check if mmdb exist in path, download automatically if it doesnt
    logger.info("Checking if MMDB exists in path...")

    mmdb_tracker = MMDB_TRACKER()
    if not mmdb_tracker.last_update_expired() and os.path.exists(
        settings.MAXMIND_MMDB_DATABASE_PATH
    ):
        logger.info("MMDB is up to date, download function skipped!")
        return

    logger.info(
        "MMDB not up to date, Running function to download/update GeoLite2 MMDB..."
    )

    license_key = settings.MAXMIND_LICENSE_KEY
    account_id = settings.MAXMIND_ACCOUNT_ID

    download_url = f"https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz"
    target_dir = os.path.dirname(settings.MAXMIND_MMDB_DATABASE_PATH)
    os.makedirs(target_dir, exist_ok=True)

    archive_path = os.path.join(target_dir, "GeoLite2-City.tar.gz")

    # Use HTTP Basic Auth to authenticate (equivalent to wget --user/--password)
    response = requests.get(download_url, stream=True, auth=(account_id, license_key))
    if response.status_code != 200:
        logger.fatal(f"Failed to download GeoLite2 database: {response.text}")
        return

    with open(archive_path, "wb") as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)

    # Extract the .mmdb file from the tar.gz archive
    import tarfile

    with tarfile.open(archive_path, "r:gz") as tar:
        for member in tar.getmembers():
            if member.name.endswith(".mmdb"):
                member.name = os.path.basename(member.name)  # Remove path
                tar.extract(member, target_dir)
                mmdb_path = os.path.join(target_dir, member.name)
                # Move/rename to the path expected by your app
                shutil.move(mmdb_path, settings.MAXMIND_MMDB_DATABASE_PATH)
                break

    # Clean up
    os.remove(archive_path)
    # update age tracker
    mmdb_tracker.update_tracker()


def delete_expired_audit_logs():
    """Deletes audit logs older than the specified lifetime"""

    life_time = datetime.now(tz=timezone.utc) + timedelta(
        days=settings.AUDIT_LOGS_LIFETIME
    )
    db_generator = get_db()
    db = next(db_generator)

    try:
        db.query(AuditLog).filter(AuditLog.timestamp > life_time).delete(
            synchronize_session=False
        )
    finally:
        db_generator.close()


scheduler.add_job(download_and_update_geolite_db, "interval", days=3)
scheduler.add_job(delete_revoked_and_expired_refresh_token, "interval", hours=1)
scheduler.add_job(delete_expired_audit_logs, "interval", days=1)
