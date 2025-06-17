from twilio.rest import Client
from api.utils.settings import settings
import logging

logger = logging.getLogger(__name__)


client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)


def send_sms_message(phone_number: str, message: str):
    try:
        sms_message = client.messages.create(
            body=message, from_=settings.TWILIO_PHONE_NUMBER, to=phone_number
        )
        logger.info(
            f"Successfuly delivered SMS to {phone_number}. Message SID: {sms_message.sid}"
        )
    except Exception as e:
        logger.error(f"Failed to send SMS to user. Error: {e}")
