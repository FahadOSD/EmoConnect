from django.db import models
from django.conf import settings


# models
class TransactionModel(models.Model):
    PLATFORM_CHOICES = [
        ('google', 'Google Play'),
        ('apple', 'Apple App Store'),
    ]
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    platform = models.CharField(max_length=10, choices=PLATFORM_CHOICES)
    product_id = models.CharField(max_length=100)  # e.g. "premium_monthly"
    purchase_token = models.TextField()            # token/receipt from mobile
    status = models.CharField(max_length=50)       # active, expired, refunded, etc.
    purchased_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.user.email} - {self.product_id} ({self.platform})"
    


class Subscription(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    is_active = models.BooleanField(default=False)  # Subscription active status
    started_at = models.DateTimeField(null=True, blank=True)  # Subscription start date
    expires_at = models.DateTimeField(null=True, blank=True)  # Subscription expiry date
    stripe_customer_id = models.CharField(max_length=255, null=True, blank=True)  # Stripe customer ID
    status_is = models.CharField(max_length=255, null=True, blank=True)
    # Trial information
    trial_started_at = models.DateTimeField(null=True, blank=True)  # Trial start datetime
    trial_used = models.BooleanField(default=False)  # Whether the trial has been used
 
    # Payment & Subscription Information
    payment_method_token = models.CharField(max_length=255, blank=True, null=True)  # Token for payment method (e.g., Stripe token)
    stripe_subscription_id = models.CharField(max_length=255, null=True, blank=True)  # Stripe subscription ID
    product_id = models.CharField(max_length=255, null=True, blank=True)  # Product ID
    platform = models.CharField(max_length=255, null=True, blank=True)  # Platform where subscription was made (e.g., web, iOS, Android)
    purchase_token = models.CharField(max_length=255, null=True, blank=True)  # Purchase token
    transaction_id = models.CharField(max_length=255, null=True, blank=True)  # Transaction ID
    original_transaction_id = models.CharField(max_length=255, null=True, blank=True)  # Original transaction ID
    purchase_date = models.DateTimeField(null=True, blank=True)  # Purchase date
 
    # Created/Updated info
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, related_name="+", null=True, blank=True)  # Created by
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, related_name="+", null=True, blank=True)  # Updated by
    created_at = models.DateTimeField(auto_now_add=True)  # Date created
    updated_at = models.DateTimeField(auto_now=True)  # Date updated