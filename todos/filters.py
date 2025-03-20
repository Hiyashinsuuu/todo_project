from django_filters import rest_framework as filters
from .models import Task

class TaskFilter(filters.FilterSet):
    class Meta:
        model = Task
        fields = ['is_completed', 'deadline']