from apscheduler.schedulers.asyncio import AsyncIOScheduler  # type: ignore
from sqlalchemy.exc import SQLAlchemyError
import logging
from datetime import datetime, timezone
from db.database import get_db
import os
import requests
import gzip
import shutil
from api.utils.settings import settings


scheduler = AsyncIOScheduler()
logger = logging.getLogger()


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
    # You must have a MaxMind license key (get it from your MaxMind account)
    license_key = settings.MAXMIND_LICENSE_KEY
    # do wget request to get the download URL, pass 'user' and 'password' (i.e --user='maxmind account id', --password='maxmind license key')
    download_url = f"https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz"
    target_dir = os.path.dirname(settings.MAXMIND_MMDB_DATABASE_PATH)
    os.makedirs(target_dir, exist_ok=True)

    archive_path = os.path.join(target_dir, "GeoLite2-City.tar.gz")

    # Download the archive
    response = requests.get(download_url, stream=True)
    if response.status_code != 200:
        raise Exception(f"Failed to download GeoLite2 database: {response.text}")

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


# Schedule the job to run once a week (or as needed)
scheduler.add_job(download_and_update_geolite_db, "interval", weeks=1)


# Schedule the job to run every hour
scheduler.add_job(delete_revoked_and_expired_refresh_token, "interval", hours=1)
