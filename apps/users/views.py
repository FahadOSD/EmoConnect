import logging
import secrets
from urllib.parse import urlencode

import requests
from allauth.socialaccount.providers.apple.views import AppleOAuth2Adapter
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from dj_rest_auth.registration.views import SocialLoginView
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework import status, viewsets
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.parsers import JSONParser
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from .models import CustomUser, EmailOTP
from .serializers import (
    CustomUserSerializer,
    ForgetPasswordSerializer,
    LoginSerializer,
    LogoutSerializer,
)

from .services import (
    AppleOAuthService,
    EmailService,
    GoogleOAuthService,
    PasswordResetService,
    UpdateService,
)

logger = logging.getLogger(__name__)
User = get_user_model()


# ==============================
# 🔹 Helper: JWT tokens
# ==============================
def get_tokens_for_user(user):
    """Generate JWT tokens"""
    refresh = RefreshToken.for_user(user)
    return {"refresh": str(refresh), "access": str(refresh.access_token)}


# ==============================
# 🔹 User Management (CRUD)
# ==============================
class CustomUserView(ModelViewSet):
    """
    This viewset provides CRUD operations for the CustomUser model.
    """

    queryset = CustomUser.objects.all()
    permission_classes = [AllowAny]
    serializer_class = CustomUserSerializer

    def get_permissions(self):
        if self.action in ["create", "register"]:
            self.permission_classes = [AllowAny]
        else:
            self.permission_classes = [IsAuthenticated]
        return super().get_permissions()

    def get_queryset(self):
        try:
            user = self.request.user
            qs = super().get_queryset()

            if not user.is_staff:
                qs = qs.filter(email=user.email)
            return qs
        except Exception as e:
            raise e

    @action(detail=False, methods=["post"])
    def register(self, request):
        serializer = CustomUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        secure_token, secure_pin = EmailService.send_code_to_email(
            request.data.get("email")
        )
        EmailService.cache_token_and_pin(serializer, secure_token, secure_pin)

        return Response({"secure_token": secure_token}, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        pin = request.data.get("pin")
        secure_token = request.data.get("secure_token")
        if not pin or not secure_token:
            return Response(
                {"message": "Pin or secure token is not provided"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        result = EmailService.complete_registration(secure_token, pin)

        if result["success"]:
            return Response(
                {"message": "User is created successfully"},
                status=status.HTTP_201_CREATED,
            )

        return Response({"error": result["error"]}, status=400)

    def update(self, request, *args, **kwargs):
        """
        Update the user instance, handle email change and send verification PIN if necessary.
        If email is provided, send a verification PIN and cache the token.
        """
        try:
            if "email" not in request.data:
                return super().update(request, *args, **kwargs)

            instance = self.get_object()
            if instance.email != request.data.get("email"):
                partial = kwargs.pop("partial", False)
                data = request.data.copy()
                data.pop("email")
                serializer = self.get_serializer(instance, data=data, partial=partial)
                serializer.is_valid(raise_exception=True)
                secure_token, secure_pin = EmailService.send_code_to_email(
                    request.data.get("email")
                )
                UpdateService.cache_token_and_pin(
                    secure_token, secure_pin, request.data.get("email")
                )
                self.perform_update(serializer)

                if getattr(instance, "_prefetched_objects_cache", None):
                    # If 'prefetch_related' has been applied to a queryset, we need to
                    # forcibly invalidate the prefetch cache on the instance.
                    instance._prefetched_objects_cache = {}

                return Response(
                    {"secure_token": secure_token, "message": "Email verification sent"}
                )

            request.data.pop("email")
            return super().update(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {"error": f"Error during update: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST,
            )


# ==============================
# 🔹 Google Auth Views
# ==============================
@api_view(["GET"])
@permission_classes([AllowAny])
def google_auth_url(request):
    """
    Generate Google OAuth URL for frontend
    Frontend should redirect user to this URL
    """
    try:
        google_settings = settings.SOCIALACCOUNT_PROVIDERS["google"]["APP"]
        client_id = google_settings["client_id"]

        redirect_uri = request.build_absolute_uri("/auth/google/callback/")

        google_oauth_url = "https://accounts.google.com/o/oauth2/auth"

        state = secrets.token_urlsafe(32)
        request.session["oauth_state"] = state

        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid email profile",
            "response_type": "code",
            "access_type": "offline",
            "prompt": "consent",
            "state": state,
        }

        auth_url = f"{google_oauth_url}?{urlencode(params)}"

        return Response(
            {
                "auth_url": auth_url,
                "state": state,
                "message": "Redirect user to this URL for Google authentication",
            }
        )

    except Exception as e:
        logger.error(f"Error occure generating Google auth url: {e}", exc_info=True)
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET"])
@permission_classes([AllowAny])
def google_auth_callback(request):
    """
    Handle Google OAuth callback
    Exchange authorization code for tokens and create/login user
    """
    try:
        # Get authorization code from query params
        code = request.GET.get("code")
        state = request.GET.get("state")
        if not code:
            return Response(
                {"error": "Authorization code not provided"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if request.session.get("oauth_state") != state:
            return Response(
                {"message": "Token is missing or doesn't match."},
                status=status.HTTP_403_FORBIDDEN,
            )

        redirect_uri = request.build_absolute_uri("/auth/google/callback/")
        access_token = GoogleOAuthService.exchange_code_for_token(code, redirect_uri)
        user_data = GoogleOAuthService.get_user_info(access_token)
        user = GoogleOAuthService.get_or_create_data(user_data)

        # Generate JWT tokens
        tokens = get_tokens_for_user(user)

        # Prepare response data
        response_data = {
            "tokens": tokens,
            "user": {
                "id": user.id,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
            },
            "message": "Successfully authenticated with Google",
        }

        return Response(response_data)

    except Exception as e:
        logger.error(f"Error occure in Google auth callback: {e}", exc_info=True)
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# ==============================
# 🔹 Google Auth (App SDK Token Flow)
# ==============================
class GoogleLoginView(SocialLoginView):
    """
    Google social login endpoint for mobile/SPA clients.
    Usage:
        - POST to this endpoint with a valid Google access_token in the body:
            { "access_token": "GOOGLE_ACCESS_TOKEN" }
        - The access_token must be obtained from Google Sign-In SDK (not the OAuth code).
        - If the token is invalid/expired, returns 400 with error details.
    """

    adapter_class = GoogleOAuth2Adapter
    client_class = OAuth2Client
    parser_classes = [JSONParser]

    def post(self, request, *args, **kwargs):
        access_token = request.data.get("access_token")
        if not access_token:
            return Response(
                {"error": "Missing access_token in request body."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            return super().post(request, *args, **kwargs)
        except Exception as e:
            return Response(
                {"error": f"Google login failed: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST,
            )


# ==============================
# 🔹 Apple Auth (Web Redirect Flow)
# ==============================
@api_view(["GET"])
@permission_classes([AllowAny])
def apple_auth_url(request):
    """
    Generate Apple OAuth URL for frontend to redirect users for authentication.
    """
    client_id = settings.SOCIALACCOUNT_PROVIDERS["apple"]["APPS"][0]["client_id"]
    redirect_uri = request.build_absolute_uri("/auth/apple/callback/")
    state = secrets.token_urlsafe(32)
    request.session["oauth_state"] = state

    apple_oauth_url = "https://appleid.apple.com/auth/authorize"
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code id_token",
        "scope": "email name",
        "state": state,
    }
    return Response(
        {"auth_url": f"{apple_oauth_url}?{urlencode(params)}", "state": state}
    )


@api_view(["GET"])
@permission_classes([AllowAny])
def apple_auth_callback(request):
    """
    Handle Apple OAuth callback. Exchange the code for tokens and fetch user data.
    """
    code = request.GET.get("code")
    state = request.GET.get("state")

    if not code or request.session.get("oauth_state") != state:
        return Response(
            {"error": "Invalid or missing state/code"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    redirect_uri = request.build_absolute_uri("/auth/apple/callback/")
    access_token, id_token = AppleOAuthService.exchange_code_for_token(
        code, redirect_uri
    )
    user_data = AppleOAuthService.decode_id_token(id_token)
    user = AppleOAuthService.get_or_create_user(user_data)

    tokens = get_tokens_for_user(user)
    return Response({"tokens": tokens, "user": CustomUserSerializer(user).data})


# ==============================
# 🔹 Apple Auth (App SDK Token Flow)
# ==============================
class AppleLogin(SocialLoginView):
    """
    Handles Apple OAuth2 login using the App SDK token flow.
    """

    adapter_class = AppleOAuth2Adapter
    client_class = OAuth2Client
    parser_classes = [JSONParser]


# ==============================
# 🔹 Logout
# ==============================
@api_view(["POST"])
def logout(request):
    """
    Blacklist refresh token and clear the session for logging out users.
    """
    serializer = LogoutSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    try:
        refresh_token = request.data.get("refresh_token")
        token = RefreshToken(refresh_token)
        token.blacklist()

        if hasattr(request, "session"):
            request.session.flush()

        return Response({"success": True, "message": "Successfully logged out"})
    except TokenError:
        return Response(
            {"success": False, "message": "Invalid token"},
            status=status.HTTP_400_BAD_REQUEST,
        )
    except Exception as e:
        logger.error(f"Error during logout: {e}", exc_info=True)
        return Response(
            {"success": False, "message": "Internal Error"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


# ==============================
# 🔹 Password Reset Views
# ==============================
@api_view(["POST"])
def forgot_password_request(request):
    """
    Initiates password reset process for the user.
    """
    try:
        serializer = ForgetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = request.data.get("email").strip().lower()

        success, message, error = PasswordResetService.initiate_password_reset(email)

        if not success and error == "rate_limit":
            return Response(
                {"error": message}, status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        if not success and error:
            return Response(
                {"error": message}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        return Response({"message": message}, status=status.HTTP_200_OK)

    except Exception as e:
        return Response(
            {"error": f"Error processing password reset request: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@api_view(["POST"])
def verify_reset_pin(request):
    """
    Verifies reset pin and provides a reset token.
    """
    email = request.data.get("email").strip().lower()
    pin = request.data.get("pin").strip()

    if not email or not pin or len(pin) != 6 or not pin.isdigit():
        return Response(
            {"error": "Invalid email or PIN format"}, status=status.HTTP_400_BAD_REQUEST
        )

    success, message, reset_token = PasswordResetService.verify_reset_pin(email, pin)

    if not success:
        return Response({"error": message}, status=status.HTTP_400_BAD_REQUEST)

    return Response(
        {"message": message, "reset_token": reset_token}, status=status.HTTP_201_CREATED
    )


@api_view(["POST"])
def reset_password(request):
    """
    Resets the user's password using the reset token.
    """
    reset_token = request.data.get("reset_token").strip()
    new_password = request.data.get("new_password")
    confirm_password = request.data.get("confirm_password")

    if not reset_token or not new_password:
        return Response(
            {"error": "Reset token and new password are required"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if new_password != confirm_password:
        return Response(
            {"error": "Passwords do not match"}, status=status.HTTP_400_BAD_REQUEST
        )

    success, message = PasswordResetService.reset_password(
        reset_token, new_password, confirm_password
    )

    if not success:
        if "Invalid or expired reset session" in message:
            return Response({"error": message}, status=status.HTTP_401_UNAUTHORIZED)
        return Response({"error": message}, status=status.HTTP_400_BAD_REQUEST)

    return Response({"message": message}, status=status.HTTP_200_OK)
