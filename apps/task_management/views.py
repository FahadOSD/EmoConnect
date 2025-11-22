from .models import Task
from .serializers import TaskSerializer
from rest_framework.viewsets import ModelViewSet
from rest_framework.permissions import IsAuthenticated
from .tasks import send_task_notification
from datetime import datetime
from django.utils import timezone


# Create your views here.
class TaskViewSet(ModelViewSet):
    """
    ViewSet for Task model providing CRUD operations.
    """
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated] 
    
    def get_queryset(self):
        # queryset = Task.objects.filter(user=self.request.user)
        # status = self.request.query_params.get('status', None)
        # category = self.request.query_params.get('category', None)
        user = getattr(self.request, "user", None)
        if user is None or not user.is_authenticated:
            return Task.objects.none()
        queryset = Task.objects.filter(user=user)
        status = self.request.query_params.get('status', None)
        category = self.request.query_params.get('category', None)
        
        if status:
            queryset = queryset.filter(status=status)
        if category:
            queryset = queryset.filter(category=category)
            
        return queryset
    
    def perform_create(self, serializer):
        # Automatically assign the currently authenticated user to the task
        Task = serializer.save(user=self.request.user)

        # Schedule the notification if the task has a due date and time
        if Task.due_date and Task.due_time:
            # Convert due date and time to a datetime object
            due_time = datetime.combine(Task.due_date, Task.due_time)
            
            # Schedule the Celery task to send notification at the due time
            send_task_notification.apply_async(args=[Task.id], eta=due_time)