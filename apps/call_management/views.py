from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from .models import Call
from .serializers import CallSerializer

class CallViewSet(viewsets.ModelViewSet):
    queryset = Call.objects.all()
    serializer_class = CallSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Optionally filter calls by the current user.
        """
        return Call.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        """
        Override the default create behavior to save the call and associate it with the current user.
        """
        serializer.save(user=self.request.user)
