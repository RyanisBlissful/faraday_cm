# authentication/email_utils.py
import logging
from typing import Optional
import requests
from django.conf import settings

logger = logging.getLogger(__name__)

# OAuth2 + Graph endpoints
GRAPH_TOKEN_URL = (
    f"https://login.microsoftonline.com/{settings.AZURE_TENANT_ID}/oauth2/v2.0/token"
)
GRAPH_SENDMAIL_URL = "https://graph.microsoft.com/v1.0/users/{sender}/sendMail"

class EmailConfigError(RuntimeError):
    """Raised when required email/Graph configuration is missing."""

def _require(value: Optional[str], name: str) -> str:
    if not value:
        raise EmailConfigError(f"Missing required setting: {name}")
    if not isinstance(value, str):
        raise EmailConfigError(f"{name} must be a string, got {type(value).__name__}")
    return value

def get_access_token() -> str:
    """Acquire an app-only access token for Microsoft Graph using client credentials."""
    client_id = _require(settings.AZURE_CLIENT_ID, "AZURE_CLIENT_ID")
    client_secret = _require(settings.AZURE_CLIENT_SECRET, "AZURE_CLIENT_SECRET")

    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials",
    }

    resp = requests.post(GRAPH_TOKEN_URL, data=data, timeout=15)
    if resp.status_code >= 400:
        try:
            logger.error("Graph token error %s: %s", resp.status_code, resp.text)
        except Exception:
            logger.error("Graph token error %s (no body)", resp.status_code)
        resp.raise_for_status()

    token = resp.json().get("access_token")
    if not token:
        raise EmailConfigError("Graph token response missing 'access_token'.")
    return token

def send_verification_email(to_email: str, subject: str, html_content: str) -> None:
    """
    Send an HTML email via Microsoft Graph's sendMail endpoint.
    - Uses the mailbox defined by settings.EMAIL_ADDRESS as the sender.
    - Raises requests.HTTPError if Graph returns a non-success status.
    """
    sender = settings.EMAIL_ADDRESS if isinstance(settings.EMAIL_ADDRESS, str) else settings.EMAIL_HOST_USER
    sender = _require(sender, "EMAIL_ADDRESS")

    access_token = get_access_token()
    url = GRAPH_SENDMAIL_URL.format(sender=sender)
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    payload = {
        "message": {
            "subject": subject,
            "body": {"contentType": "HTML", "content": html_content},
            "toRecipients": [{"emailAddress": {"address": to_email}}],
        },
        "saveToSentItems": "false",
    }

    resp = requests.post(url, headers=headers, json=payload, timeout=15)
    resp.raise_for_status()
    logger.info("Verification email queued via Graph for %s", to_email)
