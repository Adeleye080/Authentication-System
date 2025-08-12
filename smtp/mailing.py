"""
SMTP Utility Module
"""

from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
from api.utils.settings import settings
from typing import Dict
from pydantic import EmailStr
from smtp.decorators import send_email_retry_on_failure_with_fallback
from datetime import datetime
import logging


logger = logging.getLogger(__name__)

MAIL_USERNAME = settings.EMAIL_ADDRESS
MAIL_PASSWORD = settings.EMAIL_PASSWORD
MAIL_FROM = settings.EMAIL_ADDRESS
MAIL_PORT = settings.SMTP_PORT
MAIL_SERVER = settings.SMTP_SERVER


# General context for all emails
general_email_context = {
    "termsUrl": settings.COMPANY_TERMS_OF_SERVICE_URL,
    "privacyUrl": settings.COMPANY_PRIVACY_POLICY_URL,
    "companyAddress": settings.COMPANY_ADDRESS,
    "companyName": settings.COMPANY_NAME,
    "currentYear": datetime.now().year,
    "companyLogoUrl": settings.COMPANY_LOGO_URL,
}


@send_email_retry_on_failure_with_fallback(retries=2, delay=2, use_backup=False)
async def send_mail(
    recipient: EmailStr,
    subject: str,
    template_name: str,
    template_context: Dict = {},
):

    conf = ConnectionConfig(
        MAIL_USERNAME=MAIL_USERNAME,
        MAIL_PASSWORD=MAIL_PASSWORD,
        MAIL_FROM=MAIL_FROM,
        MAIL_PORT=MAIL_PORT,
        MAIL_SERVER=MAIL_SERVER,
        MAIL_STARTTLS=True,
        MAIL_SSL_TLS=False,
        USE_CREDENTIALS=True,
        VALIDATE_CERTS=True,
        MAIL_FROM_NAME=settings.COMPANY_NAME,
        TEMPLATE_FOLDER=settings.MJML_TEMPLATE_DIR,
    )

    # update context with the generate context
    template_context.update(**general_email_context)

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

    try:
        await fast_mail.send_message(message, template_name=template_name)
        logger.info(f"✔️ Successfully devivered mail ({subject}) to {receiver}")
    except Exception as exc:
        logger.error(
            f"{exc.__class__.__name__} occurred while sending mail ({subject}) to {receiver}"
        )
        raise exc


def _send_email_smtp_backup(
    recipient: EmailStr,
    subject: str,
    template_name: str,
    template_context: Dict = {},
):
    """
    Backup function to send mail if FastAPI-Mail fails.
    Automatically called by the `send_email_retry_on_failure_with_fallback` decorator
    if `use_backup` is `True` (True by default)

    Please DO NOT CALL THIS FUNCTION! Let the decorator handle it
    """

    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    import smtplib
    from main import email_templates

    # Render the template using Jinja2
    template = email_templates.get_template(template_name)
    # Render the template with the given context
    body = template.render(template_context)

    message = MIMEMultipart()
    message["From"] = MAIL_FROM
    message["To"] = recipient
    message["Subject"] = subject
    message["Reply-To"] = MAIL_FROM
    message.attach(MIMEText(body, "html"))

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(MAIL_USERNAME, MAIL_PASSWORD)
            text = message.as_string()
            server.sendmail(MAIL_FROM, recipient, text)
            logger.info(
                f"✔️ Send mail backup function successfully devivered mail ({subject}) to {recipient}"
            )
    except Exception as e:
        logger.error(
            f"Send mail backup function failed to send ({subject}) mail to {recipient} due to {e}"
        )


def _send_email_mailgun_backup(
    recipient: EmailStr,
    subject: str,
    template_name: str,
    template_context: Dict = {},
):

    import requests
    from api.utils.settings import settings
    from main import email_templates

    # Render the template using Jinja2
    template = email_templates.get_template(template_name)
    # Render the template with the given context
    html_content = template.render(template_context)

    data = {
        "from": settings.COMPANY_NAME,
        "to": recipient,
        "subject": subject,
        "html": html_content,
    }

    try:
        response = requests.post(
            f"https://api.mailgun.net/v3/{settings.MAILGUN_DOMAIN}/messages",
            auth=(
                "api",
                settings.MAILGUN_API_KEY,
            ),  # Authenticate using 'api' and your API key
            data=data,
        )

        # Check the response
        if response.status_code == 200:
            logger.info(
                f"✔️ Mailgun successfully devivered mail ({subject}) to {recipient}"
            )
        else:
            logger.error(
                f"Mailgun failed to deliver mail ({subject}) to {recipient}. ERROR_CODE {response.status_code}, REASON {response.reason}"
            )

    except Exception as exc:
        logger.error(f"Mail Gun mailing function failed with Exception: {exc}")
