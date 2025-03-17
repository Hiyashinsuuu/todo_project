from django.contrib import admin
from .models import Task, Project 

@admin.register(Task)
class TaskAdmin(admin.ModelAdmin):
    list_display = ('title', 'description', 'is_important', 'is_completed', 'user')  
    list_display_links = ('title',)  # Title is clickable to edit full task details
    list_editable = ('description','is_important', 'is_completed')  # These fields are editable in list view
    list_filter = ('is_completed', 'project')  # Add filters
    search_fields = ('title', 'user__username')  # Search bar for tasks and usernames

@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ["id", "get_name"]

    def get_name(self, obj):
        return Project.DEFAULT_CHOICES.get(obj.id, "Unknown")
    get_name.short_description = "Project Name"

