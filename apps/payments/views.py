from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.utils import timezone
from datetime import timedelta

from .serializers import VerifyPurchaseSerializer
from .models import TransactionModel
from drf_yasg.utils import swagger_auto_schema


class VerifyPurchaseView(APIView):
    @swagger_auto_schema(request_body=VerifyPurchaseSerializer, tags=['Payments'])
    def post(self, request):
        serializer = VerifyPurchaseSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        # For now, mock verification (replace with Google/Apple API later)
        is_valid = True  # pretend we checked with store

        if not is_valid:
            return Response({"detail": "Invalid purchase"}, status=status.HTTP_400_BAD_REQUEST)

        # Create a transaction
        transaction = TransactionModel.objects.create(
            user=request.user,
            platform=data['platform'],
            product_id=data['product_id'],
            purchase_token=data['token'],
            status="active",
            expires_at=timezone.now() + timedelta(days=30)  # fake 1-month expiry
        )

        # Update user subscription
        request.user.paid_user = True
        request.user.current_plan = data['product_id']
        request.user.current_period_start = timezone.now()
        request.user.current_period_end = transaction.expires_at
        request.user.save()

        return Response({
            "status": "active",
            "plan": request.user.current_plan,
            "expires_at": request.user.current_period_end
        })