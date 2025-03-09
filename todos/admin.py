from django.contrib import admin
from .models import Task, Category 

@admin.register(Task)
class TaskAdmin(admin.ModelAdmin):
    list_display = ('title', 'description', 'priority', 'is_important', 'is_completed', 'user')  
    list_display_links = ('title',)  # Title is clickable to edit full task details
    list_editable = ('description', 'priority', 'is_important', 'is_completed')  # These fields are editable in list view
    list_filter = ('priority', 'is_completed', 'category')  # Add filters
    search_fields = ('title', 'user__username')  # Search bar for tasks and usernames

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'user', 'created_at')
    search_fields = ('name', 'user__username')
