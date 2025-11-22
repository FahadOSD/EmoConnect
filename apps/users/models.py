from datetime import timedelta

from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import AbstractUser, BaseUserManager, PermissionsMixin
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone


# ==============================
# 🔹 Custom User Manager Model
# ==============================
class CustomUserManager(BaseUserManager):
    """Custom manager for user model with email as unique identifier."""

    def _create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.password = make_password(password)  # securely hash password
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        """Create and save a regular user."""
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password=None, **extra_fields):
        """Create and save a superuser with given email and password."""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")
        return self._create_user(email, password, **extra_fields)


# ==============================
# 🔹 Custom User Model
# ==============================
class CustomUser(AbstractUser):
    """Custom user model that uses email instead of username."""

    username = models.CharField(
        max_length=150,
        unique=True,
        null=True,
        blank=True,
        help_text="Username auto-generated from email",
    )
    email = models.EmailField(unique=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def __str__(self):
        return self.email

    def validate_email(self):
        if not self.email:
            raise ValidationError("Email is required")

    class Meta:
        db_table = "custom_user"  # Custom table name
        verbose_name = "User"
        verbose_name_plural = "Users"


# ==============================
# 🔹 Email OTP Model
# ==============================
class EmailOTP(models.Model):
    email = models.EmailField()
    otp = models.CharField(max_length=6)
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_valid(self):
        """Check if OTP is valid (not expired and not used)."""
        expiration_time = self.created_at + timedelta(
            minutes=5
        )  # OTP expires in 5 minutes
        return not self.is_used and timezone.now() < expiration_time

    def __str__(self):
        return f"OTP for {self.email} - {'Used' if self.is_used else 'Unused'}"
