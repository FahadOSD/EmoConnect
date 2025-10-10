from django.contrib import admin
from .models import Call
# Register your models here.

@admin.register(Call)
class CallAdmin(admin.ModelAdmin):
    list_display = ['id', 'call_type', 'scheduled_time', 'voice_record', 'notification_sent', 'created_at', 'updated_at']
    list_filter = ['call_type', 'notification_sent']
    search_fields = ['call_type']
    ordering = ['-created_at']
 