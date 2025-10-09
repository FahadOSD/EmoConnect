# task_management/tasks.py
from celery import shared_task
from datetime import datetime
from django.utils import timezone
from push_notifications.models import GCMDevice  # Assuming you use FCM for push notifications

@shared_task
def send_task_notification(task_id):
    from .models import Task
    
    # Fetch the task from the database
    task = Task.objects.get(id=task_id)

    # Check if the task's notification_enabled flag is set to True
    if task.notification_enabled:
        # Get the time when notification should be sent
        due_time = datetime.combine(task.due_date, task.due_time)
        
        # Ensure the time is in the future
        if due_time > timezone.now():
            # Send push notification to the user (replace with actual push notification logic)
            device = GCMDevice.objects.filter(user=task.user).first()
            if device:
                device.send_message(f"Reminder: It's time to {task.task_name}!")
