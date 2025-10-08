from .models import Task
from .serializers import TaskSerializer
from rest_framework.viewsets import ModelViewSet
from rest_framework.permissions import IsAuthenticated

# Create your views here.
class TaskViewSet(ModelViewSet):
    """
    ViewSet for Task model providing CRUD operations.
    """
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated] 
    
    def get_queryset(self):
        queryset = Task.objects.filter(user=self.request.user)
        status = self.request.query_params.get('status', None)
        category = self.request.query_params.get('category', None)
        
        
        if status:
            queryset = queryset.filter(status=status)
        if category:
            queryset = queryset.filter(category=category)
            
        return queryset
    
    def perform_create(self, serializer):
        # Automatically assign the currently authenticated user to the task
        serializer.save(user=self.request.user)