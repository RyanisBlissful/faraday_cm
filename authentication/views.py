
# authentication/views.py
import logging
from requests import HTTPError
from django.conf import settings
from django.contrib.auth import get_user_model

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView, TokenBlacklistView

from .serializers import RegisterUserSerializer, CustomTokenObtainPairSerializer
from .email_utils import send_verification_email
from .token_utils import (
    generate_email_verification_token,
    verify_email_verification_token,
    get_user_from_verified_payload,
)

logger = logging.getLogger(__name__)
User = get_user_model()




class RegisterUserView(APIView):
    throttle_class = [ScopedRateThrottle]
    throttle_scope = "register"
    def post(self, request, *args, **kwargs):
        serializer = RegisterUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Create user (inactive by default per model)
        user = serializer.save()

        # Build a signed verification token and link
        token = generate_email_verification_token(user)
        base_url = getattr(settings, "FRONTEND_BASE_URL", "http://localhost:3000")
        verify_path = getattr(settings, "VERIFY_EMAIL_PATH", "/verify-email")
        verify_url = f"{base_url.rstrip('/')}{verify_path}?token={token}"

        subject = "Verify your Faraday account"
        html_content = f"""
            <p>Hi {user.first_name or ''},</p>
            <p>Thanks for registering with Faraday_CM.</p>
            <p><a href="{verify_url}">Verify my email</a></p>
            <p>If you didn’t create this account, you can ignore this message.</p>
        """

        email_sent = False
        try:
            send_verification_email(user.email, subject, html_content)
            email_sent = True
        except HTTPError:
            logger.exception("Failed to send verification email (HTTP) for %s", user.email)
        except Exception:
            logger.exception("Failed to send verification email for %s", user.email)

        return Response(
            {
                "user": RegisterUserSerializer(user).data,
                "email_sent": email_sent,
            },
            status=status.HTTP_201_CREATED,
        )



class VerifyEmailView(APIView):    
    """
    GET /auth/verify-email/?token=...
    Validates the signed token, activates the user, and returns 200 on success.
    """
    throttle_class = [ScopedRateThrottle]
    throttle_scope = "verify-email"
    def get(self, request):
        token = request.GET.get("token")
        if not token:
            return Response({"error": "Missing token."}, status=status.HTTP_400_BAD_REQUEST)

        # Validate token
        from django.core.signing import SignatureExpired, BadSignature
        try:
            payload = verify_email_verification_token(token)
        except SignatureExpired:
            return Response({"error": "expired"}, status=status.HTTP_400_BAD_REQUEST)
        except BadSignature:
            return Response({"error": "invalid"}, status=status.HTTP_400_BAD_REQUEST)

        # Resolve user and activate
        user = get_user_from_verified_payload(payload)
        if not user:
            return Response({"error": "not-found"}, status=status.HTTP_400_BAD_REQUEST)

        if not user.is_active:
            user.is_active = True
            user.save(update_fields=["is_active"])

        return Response({"message": "Email verified successfully."}, status=status.HTTP_200_OK)



class ResendVerificationView(APIView):
    """
    POST { "email": "<address>" }
    Returns 200 with { "email_sent": true|false } without leaking account existence.
    """
    throttle_class = [ScopedRateThrottle]
    throttle_scope = "resend-verification"
    def post(self, request, *args, **kwargs):
        email = (request.data or {}).get("email")
        # Always return 200 to avoid account enumeration
        if not email:
            return Response({"email_sent": False}, status=status.HTTP_200_OK)

        user = User.objects.filter(email__iexact=email).first()
        if not user or user.is_active:
            return Response({"email_sent": False}, status=status.HTTP_200_OK)

        # Build verification token + link and send
        token = generate_email_verification_token(user)
        base_url = getattr(settings, "FRONTEND_BASE_URL", "http://localhost:3000")
        verify_path = getattr(settings, "VERIFY_EMAIL_PATH", "/verify-email")
        verify_url = f"{base_url.rstrip('/')}{verify_path}?token={token}"

        subject = "Verify your Faraday account"
        html_content = f"""
            <p>Please verify your account by clicking <a href="{verify_url}">this link</a>.</p>
        """

        try:
            send_verification_email(user.email, subject, html_content)
            return Response({"email_sent": True}, status=status.HTTP_200_OK)
        except HTTPError:
            logger.exception("Failed to resend verification email (HTTP) for %s", user.email)
        except Exception:
            logger.exception("Failed to resend verification email for %s", user.email)

        return Response({"email_sent": False}, status=status.HTTP_200_OK)


class MeView(APIView):
    """Simple authenticated endpoint that returns the current user's basic info."""
    permission_classes = [IsAuthenticated]
    throttle_class = [ScopedRateThrottle]
    throttle_scope = "login"

    def get(self, request):
        user = request.user
        data = {
            "id": user.id,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "role": getattr(user, "role", None),
        }
        return Response(data, status=status.HTTP_200_OK)

#################################################################
# token views including throttling
################################################################
class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "jwt-token"

class ThrottledTokenRefreshView(TokenRefreshView):
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "jwt-refresh"

class ThrottledTokenVerifyView(TokenVerifyView):
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "jwt-verify"

class ThrottledTokenBlacklistView(TokenBlacklistView):
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "jwt-blacklist"
