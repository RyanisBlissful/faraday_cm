# authentication/urls.py
from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
    TokenBlacklistView,
)
from .views import RegisterUserView, MeView  # <-- add MeView here

urlpatterns = [
    # Registration
    path('register-new-user/', RegisterUserView.as_view(), name='register-new-user'),

    # JWT authentication
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),

    # Logout (blacklist the refresh token)
    path('token/blacklist/', TokenBlacklistView.as_view(), name='token_blacklist'),

    # Current user info (protected)
    path('me/', MeView.as_view(), name='me'),  # <-- new
]
