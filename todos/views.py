from rest_framework import viewsets, filters, serializers, permissions
from rest_framework.views import APIView
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django_filters.rest_framework import DjangoFilterBackend
from .models import Task, Category
from .utils import notify_upcoming_tasks  
from .serializers import TaskSerializer, CategorySerializer
from django.utils.timezone import now, timedelta
from rest_framework.decorators import api_view, permission_classes
from rest_framework import status



# ✅ Get all tasks
@api_view(["GET"])
def get_tasks(request):
    tasks = Task.objects.all()
    serializer = TaskSerializer(tasks, many=True)
    return Response(serializer.data)

# ✅ Create a new task
@permission_classes([IsAuthenticated]) 
class CreateTaskView(APIView):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer
    permission_classes = [permissions.IsAuthenticated]
    def post(self, request):
        serializer = TaskSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# ✅ Update a task
@api_view(["PUT"])
def update_task(request, task_id):
    try:
        task = Task.objects.get(id=task_id)
    except Task.DoesNotExist:
        return Response({"error": "Task not found"}, status=status.HTTP_404_NOT_FOUND)

    serializer = TaskSerializer(task, data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# ✅ Delete a task
@api_view(["DELETE"])
def delete_task(request, task_id):
    try:
        task = Task.objects.get(id=task_id)
        task.delete()
        return Response({"message": "Task deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
    except Task.DoesNotExist:
        return Response({"error": "Task not found"}, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET'])
def task_notifications(request):
    user = request.user
    notifications = notify_upcoming_tasks(user)
    return Response({'notifications': notifications})

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

