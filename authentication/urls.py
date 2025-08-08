# authentication/urls.py
from django.urls import path

from .views import (
    CustomTokenObtainPairView,
    ThrottledTokenRefreshView,
    ThrottledTokenVerifyView,
    ThrottledTokenBlacklistView,
    RegisterUserView,
    MeView,
    VerifyEmailView,
    ResendVerificationView,
)


urlpatterns = [
    # Registration
    path('register/', RegisterUserView.as_view(), name='register'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify-email'),
    path('resend-verification/', ResendVerificationView.as_view(), name='resend_verification'),

    # JWT authentication
    path('token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', ThrottledTokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', ThrottledTokenVerifyView.as_view(), name='token_verify'),
    path('token/blacklist/', ThrottledTokenBlacklistView.as_view(), name='token_blacklist'),

    # Current user info
    path('me/', MeView.as_view(), name='me'),
]

