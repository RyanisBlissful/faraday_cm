# authentication/token_utils.py
import time
from typing import Dict, Any

from django.core import signing
from django.core.signing import BadSignature, SignatureExpired
from django.conf import settings
from django.contrib.auth import get_user_model

# A unique salt to scope these signatures specifically to email verification
SALT = "faraday_cm.email_verification"

# Default token age (hours) – override in settings if desired
DEFAULT_MAX_AGE_HOURS = getattr(settings, "EMAIL_VERIFICATION_MAX_AGE_HOURS", 48)


def generate_email_verification_token(user) -> str:
    """
    Create a signed, URL-safe token that encodes minimal data:
    - uid: user's primary key (string)
    - email: user's email (case preserved)
    - ts: issued-at (seconds)
    """
    payload = {
        "uid": str(user.pk),
        "email": user.email,
        "ts": int(time.time()),
    }
    # signing.dumps produces a URL-safe string using SECRET_KEY + SALT
    return signing.dumps(payload, salt=SALT)


def verify_email_verification_token(
    token: str,
    max_age_hours: int = DEFAULT_MAX_AGE_HOURS,
) -> Dict[str, Any]:
    """
    Load and validate a token. Raises:
    - SignatureExpired if the token is older than max_age_hours
    - BadSignature if the token was tampered with or invalid
    Returns the original payload dict on success.
    """
    payload: Dict[str, Any] = signing.loads(
        token,
        salt=SALT,
        max_age=max_age_hours * 3600,
    )
    return payload


def get_user_from_verified_payload(payload: Dict[str, Any]):
    """
    Resolve the user from a verified payload.
    Returns the user instance or None if not found.
    """
    User = get_user_model()
    uid = payload.get("uid")
    if not uid:
        return None
    try:
        return User.objects.get(pk=uid)
    except User.DoesNotExist:
        return None
