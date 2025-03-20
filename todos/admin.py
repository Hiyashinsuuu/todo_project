from django.contrib import admin
from .models import Task

@admin.register(Task)
class TaskAdmin(admin.ModelAdmin):
    list_display = ('title', 'description', 'is_important', 'is_completed', 'user')  
    list_display_links = ('title',)  # Title is clickable to edit full task details
    list_editable = ('description','is_important', 'is_completed') 
    search_fields = ('title', 'user__username')  # Search bar for tasks and usernames



