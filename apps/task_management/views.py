from .models import Task
from .serializers import TaskSerializer
from rest_framework.viewsets import ModelViewSet

# Create your views here.
class TaskViewSet(ModelViewSet):
    """
    ViewSet for Task model providing CRUD operations.
    """
    serializer_class = TaskSerializer
    
    def get_queryset(self):
        queryset = Task.objects.all()
        status = self.request.query_params.get('status', None)
        category = self.request.query_params.get('category', None)
        
        if status:
            queryset = queryset.filter(status=status)
        if category:
            queryset = queryset.filter(category=category)
            
        return queryset