from django.contrib import admin
from django.urls import include, path

from django.shortcuts import redirect
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
schema_view = get_schema_view(
    openapi.Info(
        title="🤖 EMOCONNECT - Made by Md Fahad Mir",
        default_version='v1',
        description="API documentation for the EMOCONNECT project",
        
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

def redirect_to_docs(request):
    """Redirect root URL to API documentation"""
    return redirect('schema-swagger-ui')

urlpatterns = [
    path("admin/", admin.site.urls),
    # Local app routes
    path("", include("apps.users.urls")),
    path("", include("apps.task_management.urls")),


    # API Documentation
    path('api/docs/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('api/redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    path('api/swagger.json', schema_view.without_ui(cache_timeout=0), name='schema-json'),

    # Redirect root to docs
    path('', redirect_to_docs, name='root-redirect'),
]
