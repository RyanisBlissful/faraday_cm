import logging

from requests import HTTPError

from django.core import signing
from django.conf import settings
from django.shortcuts import render
from django.urls import reverse
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import get_user_model

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework  import status
from rest_framework.permissions import IsAuthenticated

from rest_framework_simplejwt.views import TokenObtainPairView

from .permissions import IsAdmin, IsManage
from .serializers import RegisterUserSerializer, CustomTokenObtainPairSerializer
from .email_utils import send_verification_email


# logging setup
logger =  logging.getLogger(__name__)




class RegisterUserView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = RegisterUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Create the user (should default to is_active=False until verified)
        user = serializer.save()

        # --- NEW: Build a signed, time-limited verification token + link ---
        # Uses Django's signing utilities. We'll verify it later in a verify view.
        token_payload = {"uid": user.id, "email": user.email}
        token = signing.dumps(token_payload, salt="email-verify")  # time-limited check happens on loads()

        # Frontend link (or fallback to localhost) – configurable via settings/.env
        base_url = getattr(settings, "FRONTEND_BASE_URL", "http://localhost:3000")
        verify_path = getattr(settings, "VERIFY_EMAIL_PATH", "/verify-email")
        verify_url = f"{base_url.rstrip('/')}{verify_path}?token={token}"

        # Example email content including the link (replace with your template later)
        subject = "Verify your Faraday account"
        html_content = f"""
            <p>Hi {user.first_name or ''},</p>
            <p>Thanks for registering with Faraday.</p>
            <p>Please verify your email by clicking the link below:</p>
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

 

class MeView(APIView):
    """
    Simple authenticated endpoint that returns the current user's basic info.
    """
    permission_classes = [IsAuthenticated]

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
    
    
class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


User = get_user_model()

class VerifyEmailView(APIView):
    def get(self, request):
        uid = request.GET.get("uid")
        token = request.GET.get("token")

        try:
            user = User.objects.get(pk=uid)
        except User.DoesNotExist:
            return Response({"error": "Invalid user ID."}, status=status.HTTP_400_BAD_REQUEST)

        if default_token_generator.check_token(user, token):
            user.is_active = True
            user.save()
            return Response({"message": "Email verified successfully."}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)


class ResendVerificationView(APIView):
    """
    POST { "email": "<user email>" }
    Returns HTTP 200 with { "email_sent": true|false }.
    - If user not found or already active → email_sent=False (avoid account enumeration).
    - If user exists and inactive → attempt to send email → true on success, false on failure.
    """

    def post(self, request, *args, **kwargs):
        email = (request.data or {}).get("email")
        # Always return 200 to avoid account enumeration
        if not email:
            return Response({"email_sent": False}, status=status.HTTP_200_OK)

        User = get_user_model()
        user = User.objects.filter(email__iexact=email).first()

        # If no user or already active, do not send email but still 200
        if not user or user.is_active:
            return Response({"email_sent": False}, status=status.HTTP_200_OK)

        # Build the verification email content
        subject = "Verify your Faraday account"
        html_content = "<p>Please verify your account.</p>"  # replace with your real template

        try:
            send_verification_email(user.email, subject, html_content)
            return Response({"email_sent": True}, status=status.HTTP_200_OK)
        except HTTPError:
            logger.exception("Failed to resend verification email (HTTP) for %s", user.email)
            return Response({"email_sent": False}, status=status.HTTP_200_OK)
        except Exception:
            logger.exception("Failed to resend verification email for %s", user.email)
            return Response({"email_sent": False}, status=status.HTTP_200_OK)
