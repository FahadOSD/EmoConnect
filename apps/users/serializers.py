import logging
import re

from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken

from .models import CustomUser, EmailOTP

# Initialize logger
logger = logging.getLogger(__name__)


# ==============================
# 🔹 Custom User Serializer
# ==============================
class CustomUserSerializer(serializers.ModelSerializer):
    """
    Serializer to handle user-related data (CustomUser).
    Includes password validation and user creation/updating logic.
    """

    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ["email", "new_password", "confirm_password"]
        extra_kwargs = {"new_password": {"write_only": True}}

    def validate(self, attrs):
        """
        Validate the provided new password against several criteria.
        Ensures that new_password and confirm_password match, meets length and complexity requirements.
        """
        try:
            if "new_password" in attrs:
                if attrs["new_password"] != attrs["confirm_password"]:
                    raise serializers.ValidationError("Passwords do not match")
                if len(attrs["new_password"]) < 8:
                    raise serializers.ValidationError(
                        "Password must be at least 8 characters long"
                    )
                if (
                    not re.search(r"[A-Za-z]", attrs["new_password"])
                    or not re.search(r"[0-9]", attrs["new_password"])
                    or not re.search(r"[^A-Za-z0-9]", attrs["new_password"])
                ):
                    raise serializers.ValidationError(
                        "Password must contain at least one letter, one digit, and one special character"
                    )
        except Exception as e:
            raise serializers.ValidationError(
                f"Error during password validation: {str(e)}"
            )
        return attrs

    def create(self, validated_data):
        """
        Create a new user instance, excluding the 'confirm_password' field and setting the user's password.
        """
        try:
            validated_data.pop("confirm_password", None)
            password = validated_data.pop("new_password")
            user = CustomUser.objects.create_user(password=password, **validated_data)
            return user
        except Exception as e:
            raise serializers.ValidationError(f"Error during user creation: {str(e)}")

    def update(self, instance, validated_data):
        """
        Update an existing user instance, handling password changes if provided.
        """
        try:
            validated_data.pop("confirm_password", None)
            password = validated_data.pop("new_password", None)
            for attr, value in validated_data.items():
                setattr(instance, attr, value)
            if password:
                instance.set_password(password)
            instance.save()
            return instance
        except Exception as e:
            raise serializers.ValidationError(f"Error during user update: {str(e)}")


# ==============================
# 🔹 Login & Logout  Serializer
# ==============================
class LoginSerializer(serializers.Serializer):
    """Serializer for logging in a user."""

    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        """Validate user credentials."""
        email = attrs.get("email")
        password = attrs.get("password")

        # Check if email exists
        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("User not found.")

        # Check password validity
        if not user.check_password(password):
            raise serializers.ValidationError("Incorrect password.")

        # Attach user to the validated data
        attrs["user"] = user
        return attrs


class LogoutSerializer(serializers.Serializer):
    """
    Serializer to handle logout by invalidating the refresh token.
    """

    refresh_token = serializers.CharField(max_length=500)


# ==============================
# 🔹 Forget Password Serializer
# ==============================
class ForgetPasswordSerializer(serializers.Serializer):
    """
    Serializer for initiating password reset via email.
    """

    email = serializers.EmailField()


# ==============================
# 🔹 Reset Password Serializer
# ==============================
class ResetPasswordSerializer(serializers.Serializer):
    """
    Serializer for resetting the user's password using a reset token.
    """

    reset_token = serializers.CharField()
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        """
        Validate the provided passwords. Ensures that new_password and confirm_password match,
        and the new password meets the required length.
        """
        try:
            if attrs["new_password"] != attrs["confirm_password"]:
                raise serializers.ValidationError("Passwords do not match")
            if len(attrs["new_password"]) < 8:
                raise serializers.ValidationError(
                    "Password must be at least 8 characters long"
                )
        except Exception as e:
            raise serializers.ValidationError(
                f"Error during password validation: {str(e)}"
            )
        return attrs
