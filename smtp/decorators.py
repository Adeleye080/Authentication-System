import time
import logging
from functools import wraps
from typing import Callable
from api.v1.models.user import User


logger = logging.getLogger(__name__)


def log_failure(recipient: str, subject: str, retries: int = 2) -> None:
    """Log decorator failure"""

    from api.v1.services import audit_log_service
    from api.v1.schemas.audit_logs import (
        AuditLogCreate,
        AuditLogEventEnum,
        AuditLogStatuses,
    )

    recipient_user = User().get_by_email(email=recipient)

    log_description = (
        f"Failed to send mail ({subject}) to {recipient} after {retries} attempts."
    )
    schema = AuditLogCreate(
        user_id=recipient_user.id,
        event=AuditLogEventEnum.MAIL_ERROR,
        description=log_description,
        ip_address=None,
        user_agent=None,
        status=AuditLogStatuses.FAILED,
    )
    audit_log_service.log_without_bgt(schema=schema)


# Simple retry decorator
def send_email_retry_on_failure_with_fallback(
    retries: int = 2, delay: int = 2, use_backup: bool = True
):
    """
    A decorator to retry the FastAPI-Mail function call after a failure.

    Falls back to Mail-Gun (if applicable) and traditional SMTPlib mail sending.

    Params:
    :param retries: the number of retries (default is 2).
    :param delay: the delay between retries in seconds (default is 2).
    :param use_backup: `Bool` Use the backup mail sending functions
    """

    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            attempt = 0
            while attempt < retries:
                try:
                    # Try to execute the function
                    return await func(*args, **kwargs)
                except Exception as e:
                    attempt += 1
                    logger.info(f"Resend attempt {attempt} failed: {e}.")
                    time.sleep(delay)  # Wait before retrying

            if not use_backup:
                logger.info("All retries failed.")

                log_failure(
                    recipient=kwargs["recipient"],
                    subject=kwargs["subject"],
                    retries=retries,
                )
            else:
                logger.info("All retries failed. Falling back to backup mail sender.")

                recipient = kwargs["recipient"]
                subject = kwargs["subject"]
                template_name = kwargs["template_name"]
                template_context = kwargs["template_context"]

                from api.utils.settings import settings

                if settings.MAILGUN_DOMAIN and settings.MAILGUN_API_KEY:
                    from smtp.mailing import _send_email_mailgun_backup

                    logger.info(
                        f"Mail Gun Config found, Using Mail-Gun as backup to send ({subject}) mail to {recipient}."
                    )

                    try:
                        _send_email_mailgun_backup(
                            recipient=recipient,
                            subject=subject,
                            template_name=template_name,
                            template_context=template_context,
                        )
                    except Exception as e:
                        logger.exception(
                            f"❌ Mailgun failed to resend mail ({subject}) to {recipient}, exception occured: {e}"
                        )
                        log_failure(
                            recipient=recipient,
                            subject=subject,
                            retries=retries,
                        )

                else:
                    from smtp.mailing import _send_email_smtp_backup

                    # Extract necessary arguments to pass to the backup function
                    try:
                        _send_email_smtp_backup(
                            recipient=recipient,
                            subject=subject,
                            template_name=template_name,
                            template_context=template_context,
                        )
                    except Exception as e:
                        logger.exception(
                            f"❌ failed to resend mail ({subject}) to {recipient}, exception occured: {e}"
                        )
                        log_failure(
                            recipient=recipient,
                            subject=subject,
                            retries=retries,
                        )

        return wrapper

    return decorator
