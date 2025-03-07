from rest_framework import viewsets, filters, serializers
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django_filters.rest_framework import DjangoFilterBackend
from .models import Task, Category
from .serializers import TaskSerializer, CategorySerializer
from django.utils.timezone import now, timedelta
from rest_framework.decorators import api_view

@api_view(['GET'])
def inbox_tasks(request):
    user = request.user
    upcoming_tasks = Task.objects.filter(user=user, deadline__gte=now(), deadline__lte=now() + timedelta(days=2), is_completed=False)
    serializer = TaskSerializer(upcoming_tasks, many=True)
    return Response(serializer.data)

@api_view(['GET'])
def progress_tracker(request):
    user = request.user
    total_tasks = Task.objects.filter(user=user).count()
    completed_tasks = Task.objects.filter(user=user, is_completed=True).count()
    return Response({'total_tasks': total_tasks, 'completed_tasks': completed_tasks})

class TaskViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = TaskSerializer
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter, filters.SearchFilter]
    filterset_fields = ['is_completed', 'is_important', 'category', 'priority', 'recurring', 'deadline']
    ordering_fields = ['deadline', 'created_at']
    search_fields = ['title', 'description']

    def get_queryset(self):
        return Task.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        task = serializer.save(user=self.request.user)
        if task.deadline and task.deadline < now():
            raise serializers.ValidationError({'deadline': "Deadline cannot be set in the past."})

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def progress(self, request):
        total_tasks = Task.objects.filter(user=request.user).count()
        completed_tasks = Task.objects.filter(user=request.user, is_completed=True).count()
        return Response({'completed_tasks': completed_tasks, 'total_tasks': total_tasks})

class CategoryViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = CategorySerializer

    def get_queryset(self):
        return Category.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)