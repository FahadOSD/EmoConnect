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