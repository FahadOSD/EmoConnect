from django.urls import path
from .views import VerifyPurchaseView

urlpatterns = [
    path('verify-payment/', VerifyPurchaseView.as_view(), name='verify_purchase'),
]