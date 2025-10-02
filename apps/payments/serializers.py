from rest_framework import serializers
from .models import TransactionModel

class VerifyPurchaseSerializer(serializers.ModelSerializer):
    class Meta:
        model = TransactionModel
        fields = '__all__'