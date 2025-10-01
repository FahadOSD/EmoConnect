import hashlib
import logging
import secrets
import time
from datetime import datetime

import jwt
import requests
from django.conf import settings
from django.core.cache import cache
from django.core.mail import send_mail
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle

from .models import CustomUser
from .serializers import CustomUserSerializer

logger = logging.getLogger(__name__)


# ==============================
# 🔹 GOOGLE OAUTH SERVICE
# ==============================
class GoogleOAuthService:
    try:

        @staticmethod
        def exchange_code_for_token(code, redirect_uri):
            """
            Exchange the OAuth code for an access token from Google.
            """
            google_settings = settings.SOCIALACCOUNT_PROVIDERS["google"]["APP"]
            client_id = google_settings["client_id"]
            client_secret = google_settings["secret"]

            token_url = "https://oauth2.googleapis.com/token"
            token_data = {
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
                "code": code,
            }

            token_response = requests.post(token_url, data=token_data)
            token_json = token_response.json()

            if "access_token" not in token_json:
                logger.error("Failed to get access token from Google")
                raise ValueError("Failed to get access token from Google")

            return token_json["access_token"]

    except Exception as e:
        logger.error(
            f"Error occure during eexchange code for token: {e}", exc_info=True
        )
        raise

    @staticmethod
    def get_user_info(access_token):
        """
        Fetch user info using the access token.
        """
        try:
            user_info_url = f"https://www.googleapis.com/oauth2/v2/userinfo?access_token={access_token}"
            user_response = requests.get(user_info_url)
            return user_response.json()
        except Exception as e:
            logger.error(f"Error occure during user info: {e}", exc_info=True)

    @staticmethod
    def get_or_create_data(user_data):
        """
        Get or create a user using provided user data.
        """
        try:
            # Try to find user by email first
            user = CustomUser.objects.get(email=user_data["email"])
        except CustomUser.DoesNotExist:
            # User doesn't exist, create new one using email as username
            user = CustomUser.objects.create_user(
                email=user_data["email"],
                first_name=user_data.get("given_name", ""),
                last_name=user_data.get("family_name", ""),
                password=None,
            )
        return user


# ==============================
# 🔹 APPLE OAUTH SERVICE
# ==============================
class AppleOAuthService:
    @staticmethod
    def generate_client_secret():
        """
        Generate Apple client_secret (JWT signed with private key)
        """
        apple_settings = settings.SOCIALACCOUNT_PROVIDERS["apple"]["APPS"][0]

        headers = {"kid": apple_settings["key"]}
        payload = {
            "iss": apple_settings["team_id"],
            "iat": int(time.time()),
            "exp": int(time.time()) + 86400 * 180,  # 180 days validity
            "aud": "https://appleid.apple.com",
            "sub": apple_settings["client_id"],
        }

        client_secret = jwt.encode(
            payload,
            apple_settings["settings"]["certificate_key"],  # .p8 private key
            algorithm="ES256",
            headers=headers,
        )
        return client_secret

    @staticmethod
    def exchange_code_for_token(code, redirect_uri):
        """
        Exchange authorization code for Apple access_token & id_token
        """
        try:
            apple_settings = settings.SOCIALACCOUNT_PROVIDERS["apple"]["APPS"][0]
            token_url = "https://appleid.apple.com/auth/token"

            data = {
                "client_id": apple_settings["client_id"],
                "client_secret": AppleOAuthService.generate_client_secret(),
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": redirect_uri,
            }

            response = requests.post(token_url, data=data)
            token_data = response.json()

            if "error" in token_data:
                logger.error(f"Apple token error: {token_data}")
                raise ValueError("Failed to exchange code for token")

            return token_data
        except Exception as e:
            logger.error(f"Error during Apple token exchange: {e}", exc_info=True)
            raise

    @staticmethod
    def get_user_info(id_token):
        """
        Decode Apple id_token (JWT) to extract user info
        """
        try:
            user_data = jwt.decode(id_token, options={"verify_signature": False})
            return user_data
        except Exception as e:
            logger.error(f"Error decoding Apple id_token: {e}", exc_info=True)
            return {}

    @staticmethod
    def get_or_create_user(user_data):
        """
        Create or get user from DB using Apple user data
        """
        email = user_data.get("email")
        if not email:
            raise ValueError("No email found in Apple response")

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            user = CustomUser.objects.create_user(
                email=email,
                first_name=user_data.get("name", {}).get("firstName", ""),
                last_name=user_data.get("name", {}).get("lastName", ""),
                password=None,
            )
        return user


# ==============================
# 🔹 EMAIL SERVICE
# ==============================
class PasswordResetThrottle(AnonRateThrottle):
    rate = "3/min"


class EmailService:
    @staticmethod
    def send_code_to_email(email):
        """
        Sends a verification email with a secure PIN to the provided email address.
        Generates a secure token and PIN for the user.
        """
        try:
            secure_token = PasswordResetService.generate_secure_token()
            secure_pin = PasswordResetService.generate_secure_pin()

            send_mail(
                subject="Email verification code",
                message=f"""Your email verification code is: {secure_pin}

    This code will expire in 15 minutes.
    If you did not request this code, please ignore this email""",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=False,
            )

            return secure_token, secure_pin
        except Exception as e:
            raise Exception(f"Error sending email: {str(e)}")

    @staticmethod
    def cache_token_and_pin(serializer, secure_token, secure_pin):
        """
        Caches the secure token and PIN along with registration data for later validation.
        """
        try:
            cache.set(
                secure_token,
                {"pin": secure_pin, "regi_data": serializer.validated_data},
            )
        except Exception as e:
            raise Exception(f"Error caching token and pin: {str(e)}")

    @staticmethod
    def validate_pin(secure_token, pin):
        """
        Validates the provided PIN by checking it against the cached token.
        """
        try:
            secure_token = cache.get(secure_token)
            if secure_token and secure_token.get("pin") == pin:
                return True
            return False
        except Exception as e:
            raise Exception(f"Error validating PIN: {str(e)}")

    @staticmethod
    def complete_registration(secure_token, pin):
        """
        Completes the registration by verifying the PIN and creating a user.
        """
        try:
            if not EmailService.validate_pin(secure_token, pin):
                return {"success": False, "error": "Invalid PIN"}
            cached_data = cache.get(secure_token)
            if not cached_data or "regi_data" not in cached_data:
                return {"success": False, "error": "Token expired"}

            regi_data = cached_data["regi_data"]
            CustomUser.objects.create_user(
                email=regi_data["email"], password=regi_data["new_password"]
            )
            cache.delete(secure_token)

            return {"success": True}
        except Exception as e:
            return {
                "success": False,
                "error": f"Error completing registration: {str(e)}",
            }


class UpdateService:
    @staticmethod
    def cache_token_and_pin(secure_token, secure_pin, email):
        """
        Caches the secure token, PIN, and email for later validation.
        """
        try:
            cache.set(secure_token, {"pin": secure_pin, "email": email})
        except Exception as e:
            raise Exception(f"Error caching token and pin: {str(e)}")

    @staticmethod
    def update_email(secure_token, pin, user):
        """
        Updates the user's email after validating the PIN and token.
        """
        try:
            if not EmailService.validate_pin(secure_token, pin):
                return {"success": False, "error": "Invalid PIN"}
            cached_data = cache.get(secure_token)
            if not cached_data:
                return {"success": False, "error": "Token expired"}
            email = cached_data["email"]
            user.email = email
            user.save(update_fields=["email"])
            cache.delete(secure_token)

            return {"success": True}
        except Exception as e:
            return {"success": False, "error": f"Error updating email: {str(e)}"}


# ==============================
# 🔹 PASSWORD RESET SERVICE
# ==============================
class PasswordResetService:
    @staticmethod
    def generate_secure_token():
        """
        Generates a secure token for password reset.
        """
        try:
            return secrets.token_urlsafe(32)
        except Exception as e:
            raise Exception(f"Error generating secure token: {str(e)}")

    @staticmethod
    def check_rate_limit_per_email(email):
        """
        Checks if the rate limit for password reset requests per email is exceeded.
        """
        try:
            attempts = cache.get(email, 0)
            if attempts > 3:
                return False
            cache.set(email, attempts + 1, timeout=3600)
            return True
        except Exception as e:
            raise Exception(f"Error checking rate limit: {str(e)}")

    @staticmethod
    def generate_secure_pin():
        """Generate cryptographically secure 6-digit PIN for password reset."""
        try:
            return "".join([str(secrets.randbelow(10)) for _ in range(6)])
        except Exception as e:
            raise Exception(f"Error generating secure PIN: {str(e)}")

    @staticmethod
    def hash_token(token):
        """Hash tokens before storing (OWASP security practice)"""
        try:
            return hashlib.sha256(token.encode()).hexdigest()
        except Exception as e:
            raise Exception(f"Error hashing token: {str(e)}")

    @staticmethod
    def send_reset_pin_email(email, secure_pin):
        """
        Sends a password reset verification email with the generated PIN.
        """
        try:
            send_mail(
                subject="Password Reset Verification Code",
                message=f"""Your password reset verification code is: {secure_pin}

        This code will expire in 15 minutes.
        If you did not request this reset, please ignore this email.

        For security, this code can only be used once.""",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=False,
            )
        except Exception as e:
            raise Exception(f"Error sending reset PIN email: {str(e)}")

    @staticmethod
    def _ensure_consistent_timing(start_time):
        """
        Ensures consistent timing to prevent timing attacks.
        """
        try:
            elapsed = time.time() - start_time
            if elapsed < 0.5:  # Minimum 500ms response time
                time.sleep(0.5 - elapsed)
        except Exception as e:
            raise Exception(f"Error ensuring consistent timing: {str(e)}")

    @classmethod
    def initiate_password_reset(cls, email):
        """
        Initiates the password reset process by checking rate limits, generating tokens and PINs,
        and sending reset PIN email.
        """
        start_time = time.time()
        STANDARD_MESSAGE = "If an account with this email exists, you will receive a password reset code shortly."
        ERROR_MESSAGE = (
            "We're experiencing technical difficulties. Please try again later."
        )
        RATE_LIMIT_MESSAGE = "Too many reset requests. Please try again later."

        try:
            # Always perform the same operations regardless of user existence
            # This prevents timing attacks and user enumeration

            # Check rate limiting per email
            if not PasswordResetService.check_rate_limit_per_email(email):
                cls._ensure_consistent_timing(start_time)
                return False, RATE_LIMIT_MESSAGE, "rate_limit"

            # Always generate token and perform database lookup (prevent timing attacks)
            secure_token = PasswordResetService.generate_secure_token()
            secure_pin = PasswordResetService.generate_secure_pin()

            try:
                user = CustomUser.objects.get(email=email)
                user_exists = True
            except CustomUser.DoesNotExist:
                user_exists = False
                # Create dummy user object to maintain consistent timing
                user = type("DummyUser", (), {"pk": 0, "email": email})

            if user_exists:
                # Clear any existing reset tokens for this user
                cache.delete(f"pwd_reset_user:{user.pk}")

                # Store hashed token with user data
                token_data = {
                    "user_id": user.pk,
                    "email": email,
                    "pin": secure_pin,
                    "created_at": datetime.now().isoformat(),
                    "attempts": 0,
                    "used": False,
                }

                # Store with hashed token as key (OWASP recommended)
                hashed_token = PasswordResetService.hash_token(secure_token)
                cache.set(
                    f"pwd_reset_token:{hashed_token}", token_data, timeout=900
                )  # 15 minutes

                # Also store user-to-token mapping for cleanup
                cache.set(f"pwd_reset_user:{user.pk}", hashed_token, timeout=900)

                # Send PIN via email (OWASP: side-channel communication)
                cls.send_reset_pin_email(email, secure_pin)

            # Ensure consistent response time (prevent timing attacks)
            cls._ensure_consistent_timing(start_time)

            return True, STANDARD_MESSAGE, None

        except Exception as e:
            cls._ensure_consistent_timing(start_time)
            return False, ERROR_MESSAGE, str(e)

    @classmethod
    def verify_reset_pin(cls, email, pin):
        """
        Verifies the PIN for a password reset request.
        """
        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return False, "Invalid credentials", None

        user_token_hash = cache.get(f"pwd_reset_user:{user.pk}")
        if not user_token_hash:
            return False, "No active reset request found", None

        token_data = cache.get(f"pwd_reset_token:{user_token_hash}")
        if not token_data:
            return False, "Reset request expired", None

        if token_data["pin"] != pin:
            token_data["attempts"] += 1

            # Lock after 3 failed attempts (OWASP: brute force protection)
            if token_data["attempts"] > 3:
                cache.delete(f"pwd_reset_token:{user_token_hash}")
                cache.delete(f"pwd_reset_user:{user.pk}")
                return (
                    False,
                    "Too many failed attempts. Please request a new reset code.",
                    None,
                )

            cache.set(f"pwd_reset_token:{user_token_hash}", token_data, timeout=900)
            return Response(
                {
                    "error": f"Invalid PIN. {3 - token_data['attempts']} attempts remaining."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Check if already used
        if token_data["used"]:
            return False, "Reset code already used", None

        # PIN verified - generate reset session token
        reset_token = cls.generate_secure_token()
        reset_data = {
            "user_id": user.pk,
            "email": email,
            "verified": True,
            "created_at": datetime.now().isoformat(),
        }

        # Store reset session (10 minutes)
        hashed_reset_token = cls.hash_token(reset_token)
        cache.set(f"pwd_reset_session:{hashed_reset_token}", reset_data, timeout=600)

        # Mark PIN as used and clean up
        token_data["used"] = True
        cache.set(f"pwd_reset_token:{user_token_hash}", token_data, timeout=900)

        return True, "PIN verified successfully", reset_token

    @classmethod
    def reset_password(cls, reset_token, new_password, confirm_password):
        # Get reset session
        hashed_token = cls.hash_token(
            reset_token,
        )
        reset_data = cache.get(f"pwd_reset_session:{hashed_token}")

        if not reset_data or not reset_data.get("verified"):
            return False, "Invalid or expired reset session"

        try:
            user = CustomUser.objects.get(pk=reset_data["user_id"])
            serializer = CustomUserSerializer(
                user,
                data={
                    "new_password": new_password,
                    "confirm_password": confirm_password,
                },
                partial=True,
            )
            serializer.is_valid(raise_exception=True)
            serializer.save()

            cache.delete(f"pwd_reset_session:{hashed_token}")
            cache.delete(f"pwd_reset_user:{user.pk}")

            # Send notification email (OWASP: notify user of password change)
            send_mail(
                subject="Password Successfully Reset",
                message=f"""Your password has been successfully reset.

    If you did not perform this action, please contact support immediately.

    Reset performed on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}""",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=True,  # Don't fail if email fails
            )

            return (
                True,
                "Password reset successfully. Please log in with your new password.",
            )

        except CustomUser.DoesNotExist:
            return False, "User not found"
        except serializers.ValidationError as e:
            return False, e.detail
