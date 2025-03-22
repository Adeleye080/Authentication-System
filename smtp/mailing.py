"""
SMTP Utility Module
"""

from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
from api.utils.settings import settings
from typing import Dict
from pydantic import EmailStr
from smtp.decorators import send_email_retry_on_failure
from premailer import transform
from datetime import datetime
import logging


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


# import base64


# def encode_image(image_path):
#     with open(image_path, "rb") as img_file:
#         encoded_string = base64.b64encode(img_file.read()).decode("utf-8")
#     return encoded_string


# Example usage:
# encoded_logo = encode_image("/home/ajiboye/Authentication-System/some-image.png")
# encoded_logo = "data:image/png;base64," + encoded_logo


@send_email_retry_on_failure(retries=2, delay=2)
async def send_mail(
    recipient: EmailStr,
    subject: str,
    template_name: str,
    template_context: Dict = {},
):

    from main import email_templates

    conf = ConnectionConfig(
        MAIL_USERNAME=settings.EMAIL_ADDRESS,
        MAIL_PASSWORD=settings.EMAIL_PASSWORD,
        MAIL_FROM=settings.EMAIL_ADDRESS,
        MAIL_PORT=settings.SMTP_PORT,
        MAIL_SERVER=settings.SMTP_SERVER,
        MAIL_STARTTLS=True,
        MAIL_SSL_TLS=False,
        USE_CREDENTIALS=True,
        VALIDATE_CERTS=True,
        MAIL_FROM_NAME=settings.COMPANY_NAME,
        TEMPLATE_FOLDER=settings.MJML_TEMPLATE_DIR,
    )

    general_email_context = {
        "termsUrl": settings.COMPANY_TERMS_OF_SERVICE_URL,
        "privacyUrl": settings.COMPANY_PRIVACY_POLICY_URL,
        "unsubscribeUrl": "http://#",  # to be removed
        "companyAddress": settings.COMPANY_ADDRESS,
        "companyName": settings.COMPANY_NAME,
        "currentYear": datetime.now().year,
        "companyLogoUrl": settings.COMPANY_LOGO_URL,
    }

    # update context with the generate context
    template_context.update(general_email_context)
    message = MessageSchema(
        subject=subject,
        recipients=[recipient],
        template_body=template_context,
        subtype=MessageType.html,
    )

    receiver = (
        template_context.get("username") + " <" + str(recipient) + ">"
        if template_context.get("username")
        else recipient
    )
    logger.info(f"Sending mail ({subject}) to {receiver} in the background")

    fast_mail = FastMail(conf)
    # html = email_templates.get_template(template_name).render(template_context)
    # message.body = transform(html)

    try:
        await fast_mail.send_message(message, template_name=template_name)
        logger.info(f"✔️ Successfully devivered mail ({subject}) to {receiver}")
    except Exception as exc:
        logger.error(
            f"{exc.__class__.__name__} occurred while sending mail ({subject}) to {receiver}"
        )
        raise exc
