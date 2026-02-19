import os
import logging
from typing import List
from google.cloud import secretmanager
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Cc, To

logger = logging.getLogger(__name__)


def get_sendgrid_api_key() -> str:
    """
    Fetch SendGrid API key from Google Secret Manager or environment variable.
    First tries to get from environment variable (for Cloud Run).
    Falls back to Secret Manager if environment variable is not set.
    """
    # Try environment variable first (recommended for Cloud Run)
    api_key = os.getenv('SENDGRID_API_KEY')
    if api_key:
        logger.debug("SendGrid API key loaded from environment variable")
        return api_key

    # Fallback to Secret Manager
    project_id = os.getenv('GCP_PROJECT_ID')
    if not project_id:
        raise ValueError("Neither SENDGRID_API_KEY nor GCP_PROJECT_ID environment variable is set")

    secret_name = os.getenv('SENDGRID_SECRET_NAME', 'sendgrid-api-key')
    secret_version = os.getenv('SENDGRID_SECRET_VERSION', 'latest')

    try:
        client = secretmanager.SecretManagerServiceClient()
        name = f"projects/{project_id}/secrets/{secret_name}/versions/{secret_version}"

        response = client.access_secret_version(request={"name": name})
        api_key = response.payload.data.decode("UTF-8")
        logger.debug("SendGrid API key loaded from Secret Manager")
        return api_key
    except Exception as e:
        raise RuntimeError("Failed to fetch SendGrid API key from Secret Manager") from e


def send_email_via_sendgrid(to_list: List[str], cc_list: List[str], mail_body: str) -> dict:
    """
    Send email using SendGrid API.
    Raises ValueError for config issues, Exception for SendGrid failures.
    """
    api_key = get_sendgrid_api_key()
    sg = SendGridAPIClient(api_key)

    from_email = os.getenv('SENDER_EMAIL')
    if not from_email:
        raise ValueError("SENDER_EMAIL environment variable not set")

    message = Mail(
        from_email=from_email,
        to_emails=[To(email) for email in to_list],
        subject=os.getenv('EMAIL_SUBJECT', 'Notification'),
        html_content=mail_body
    )

    if cc_list:
        message.cc = [Cc(email) for email in cc_list]

    response = sg.send(message)

    if response.status_code >= 300:
        body = getattr(response, 'body', None) or ""
        raise RuntimeError(
            f"SendGrid API failed with status {response.status_code}: {body}"
        )

    logger.info(f"Email sent successfully. Status code: {response.status_code}")
    return {
        "status": "success",
        "message": "Email sent successfully",
        "status_code": response.status_code
    }
