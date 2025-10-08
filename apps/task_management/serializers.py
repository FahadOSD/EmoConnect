from .models import Task
from rest_framework import serializers

class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = ['id', 'user','task_name', 'description', 'category', 'due_date', 'due_time', 'notification_enabled', 'status', 'created_at', 'updated_at']
        read_only_fields = ['user']