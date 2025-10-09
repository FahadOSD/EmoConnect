from django.db import models
from django.utils import timezone
from datetime import date, time
from apps.users.models import CustomUser 

class Task(models.Model):
    CATEGORY_CHOICES = [
        ('Health', 'Health'),
        ('Work', 'Work'),
        ('Study', 'Study'),
        ('Personal', 'Personal'),
    ]
    
    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Completed', 'Completed'),
    ]
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='tasks')
    task_name = models.CharField(max_length=255, blank=False, null=False)
    description = models.TextField(blank=True, null=True)
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES, blank=False, null=False)
    due_date = models.DateField(blank=False, null=False, default=date.today)  # Add default
    due_time = models.TimeField(blank=False, null=False, default=time(23, 59))  # Add default
    notification_enabled = models.BooleanField(default=False)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        
        return self.task_name