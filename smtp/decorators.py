import time
import logging
from functools import wraps
from typing import Callable


logger = logging.getLogger(__name__)


# Simple retry decorator
def send_email_retry_on_failure(retries: int = 3, delay: int = 2):
    """
    A decorator to retry the function call after a failure.
    Arguments:
    - retries: the number of retries (default is 3).
    - delay: the delay between retries in seconds (default is 2).
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
                    logger.info(
                        f"Attempt {attempt} failed: {e}. Retrying in {delay} seconds..."
                    )
                    time.sleep(delay)  # Wait before retrying
            # If all retries fail, raise the last exception
            if "recipient" in kwargs:
                r = kwargs.get("recipient")
            if "subject" in kwargs:
                s = kwargs.get("subject")
            logger.exception(f"❌ failed to resend mail ({s}) to {r}")

        return wrapper

    return decorator


# Logging decorator
def log_email_activity(func):
    """
    Logs the email activity, including recipient, subject, and success/failure status.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        #     try:
        #         to_email = (
        #             kwargs.get("to_email") or args[0]
        #         )  # Assuming first argument is `to_email`
        #         subject = (
        #             kwargs.get("subject") or args[1]
        #         )  # Assuming second argument is `subject`

        #         logging.info(
        #             f"Attempting to send email to {to_email} with subject: {subject}"
        #         )
        #         result = func(*args, **kwargs)
        #         logging.info(f"Email successfully sent to {to_email}")
        #         return result
        #     except Exception as e:
        #         logging.error(
        #             f"Failed to send email to {to_email} with subject: {subject}. Error: {e}"
        #         )
        #         raise

        # return wrapper
        pass
