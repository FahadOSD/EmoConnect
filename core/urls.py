from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    # Local app routes
    path("", include("apps.users.urls")),
]
