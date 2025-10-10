from django.db import models
from apps.users.models import CustomUser
from django.utils import timezone

class Call(models.Model):
    CALL_TYPE_CHOICES = [
        ('AI', 'AI'),
        ('Human', 'Human'),
    ]

    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='calls')
    call_type = models.CharField(max_length=10, choices=CALL_TYPE_CHOICES, default='AI')
    scheduled_time = models.DateTimeField()  # When the call is scheduled
    voice_record = models.FileField(upload_to='voice_records/', blank=True, null=True)  # For AI calls only
    notification_sent = models.BooleanField(default=False)  # To track if notification was sent
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.call_type} call scheduled for {self.scheduled_time}"

    # Method to check if the call time is within 30 minutes of now
    def time_until_call(self):
        return self.scheduled_time - timezone.now()

    # Method to check if the call is AI or Human
    def is_ai_call(self):
        return self.call_type == 'AI'

    def is_human_call(self):
        return self.call_type == 'Human'
