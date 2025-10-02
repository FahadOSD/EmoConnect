from django.contrib import admin
from .models import Task

# Register your models here.
@admin.register(Task)
class TaskAdmin(admin.ModelAdmin):
    list_display = ['id', 'task_name', 'category', 'status', 'due_date', 'due_time', 'notification_enabled', 'created_at']
    list_filter = ['status', 'category', 'due_date', 'notification_enabled']
    search_fields = ['task_name', 'description']
    list_editable = ['status']
    ordering = ['-created_at']
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = (
        ('Task Information', {
            'fields': ('task_name', 'description', 'category', 'status')
        }),
        ('Schedule', {
            'fields': ('due_date', 'due_time', 'notification_enabled')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )