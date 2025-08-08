import os
import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Read credentials and email settings from environment
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID")

# Microsoft Graph API endpoints
TOKEN_URL = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/oauth2/v2.0/token"
SENDMAIL_URL = "https://graph.microsoft.com/v1.0/users/{sender}/sendMail"

def get_access_token():
    """Obtain an access token from Microsoft Identity platform."""
    data = {
        "client_id": AZURE_CLIENT_ID,
        "scope": "https://graph.microsoft.com/.default",
        "client_secret": AZURE_CLIENT_SECRET,
        "grant_type": "client_credentials"
    }
    response = requests.post(TOKEN_URL, data=data)
    response.raise_for_status()
    return response.json()["access_token"]

def send_verification_email(to_email, subject, html_content):
    """Send an email using Microsoft Graph API."""
    access_token = get_access_token()
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    email_data = {
        "message": {
            "subject": subject,
            "body": {
                "contentType": "HTML",
                "content": html_content
            },
            "toRecipients": [
                {
                    "emailAddress": {
                        "address": to_email
                    }
                }
            ]
        },
        "saveToSentItems": "true"
    }

    url = SENDMAIL_URL.format(sender=EMAIL_ADDRESS)
    response = requests.post(url, headers=headers, json=email_data)
    response.raise_for_status()
    print(f"Verification email sent to {to_email}.")
