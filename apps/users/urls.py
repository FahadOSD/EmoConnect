from django.urls import include, path
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from .views import (
    AppleLogin,
    CustomUserView,
    GoogleLoginView,
    apple_auth_callback,
    apple_auth_url,
    forgot_password_request,
    google_auth_callback,
    google_auth_url,
    logout,
    reset_password,
    verify_reset_pin,
)

# Creating a router for the UserViewSet
router = DefaultRouter()
router.register("", CustomUserView, basename="user")


urlpatterns = [
    # Include the router's URLs for the user-related endpoints
    path(
        "create_user/", CustomUserView.as_view({"post": "create"}), name="create_user"
    ),
    # Include user viewset URLs (list/retrieve/update)
    path("user/", include(router.urls)),
    # JWT token endpoints for login
    path("login/", TokenObtainPairView.as_view(), name="login"),
    path("login/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    # Google OAuth login
    path("auth/google/", GoogleLoginView.as_view(), name="google-login"),
    path("auth/google/url/", google_auth_url, name="google-auth-url"),
    path("auth/google/callback/", google_auth_callback, name="google-auth-callback"),
    # Apple OAuth login
    path("auth/apple/", AppleLogin.as_view(), name="apple-login"),
    path("auth/apple/url/", apple_auth_url, name="apple-auth-url"),
    path("auth/apple/callback/", apple_auth_callback, name="apple-auth-callback"),
    # Password Reset
    path("forgot-password/", forgot_password_request, name="password-reset"),
    path("password-reset/verify/", verify_reset_pin, name="verify-reset-pin"),
    path("password-reset/reset/", reset_password, name="reset-password"),
    # Logout
    path("logout/", logout, name="logout"),
]
