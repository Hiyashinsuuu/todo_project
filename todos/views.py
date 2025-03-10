from rest_framework import viewsets, filters, serializers, permissions, status, generics
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from django.contrib.auth import update_session_auth_hash, get_user_model, authenticate
from django.contrib.auth.hashers import check_password
from rest_framework.parsers import MultiPartParser, FormParser
from django.utils.timezone import now
from .models import Task, Project
from .utils import notify_upcoming_tasks
from .serializers import TaskSerializer, ProjectSerializer, SettingsSerializer

User = get_user_model()

### 🟢 DASHBOARD STATS ###
@api_view(["GET"])
@permission_classes([IsAuthenticated])  
def dashboard_stats(request):
    user = request.user  
    total_tasks = Task.objects.filter(user=user).count()
    completed_tasks = Task.objects.filter(user=user, is_completed=True).count()
    incomplete_tasks = total_tasks - completed_tasks
    important_tasks = Task.objects.filter(user=user, is_important=True).count()

    projects = Project.objects.filter(user=user)
    project_counts = {project.name: Task.objects.filter(user=user, project=project).count() for project in projects}

    return Response({
        "total_tasks": total_tasks,
        "completed_tasks": completed_tasks,
        "incomplete_tasks": incomplete_tasks,
        "important_tasks": important_tasks,
        "tasks_by_project": project_counts,
    })


### 🟢 USER SETTINGS ###
class UserSettingsView(generics.RetrieveUpdateAPIView):
    queryset = User.objects.all()
    serializer_class = SettingsSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user  

    def patch(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            if "password" in request.data:
                update_session_auth_hash(request, user)

            return Response({"message": "Account updated successfully."}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, *args, **kwargs):
        user = self.get_object()
        password = request.data.get("password")

        if not password:
            return Response({"error": "Password is required"}, status=status.HTTP_400_BAD_REQUEST)

        if not check_password(password, user.password):
            return Response({"error": "Incorrect password"}, status=status.HTTP_403_FORBIDDEN)

        user.delete()
        return Response({"message": "Account deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
    

### 🟢 UPLOAD PROFILE PICTURE ###
class UploadProfilePictureView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]  

    def post(self, request, *args, **kwargs):
        user = request.user

        if "profile_picture" not in request.FILES:
            return Response({"error": "No image uploaded"}, status=status.HTTP_400_BAD_REQUEST)

        user.profile_picture = request.FILES["profile_picture"]
        user.save()

        return Response({"message": "Profile picture updated successfully", "profile_picture": user.profile_picture.url}, status=status.HTTP_200_OK)


### 🟢 TASK MANAGEMENT ###
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_tasks(request):
    tasks = Task.objects.filter(user=request.user)  
    serializer = TaskSerializer(tasks, many=True)
    return Response(serializer.data)


class CreateTaskView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        data = request.data.copy()
        data["user"] = request.user.id  
        serializer = TaskSerializer(data=data, context={"request": request})

        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['PUT', 'PATCH'])
@permission_classes([IsAuthenticated])
def update_task(request, task_id):
    try:
        task = Task.objects.get(id=task_id, user=request.user)  
    except Task.DoesNotExist:
        return Response({"detail": "Task not found"}, status=status.HTTP_404_NOT_FOUND)

    serializer = TaskSerializer(task, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def delete_task(request, task_id):
    try:
        task = Task.objects.get(id=task_id, user=request.user)  
        task.delete()
        return Response({"message": "Task deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
    except Task.DoesNotExist:
        return Response({"error": "Task not found"}, status=status.HTTP_404_NOT_FOUND)


### 🟢 TASK NOTIFICATIONS ###
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def task_notifications(request):
    user = request.user
    notifications = notify_upcoming_tasks(user)
    return Response({"notifications": notifications})


### 🟢 PROGRESS TRACKER ###
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def progress_tracker(request):
    user = request.user
    total_tasks = Task.objects.filter(user=user).count()
    completed_tasks = Task.objects.filter(user=user, is_completed=True).count()
    return Response({"total_tasks": total_tasks, "completed_tasks": completed_tasks})


### 🟢 TASK VIEWSET ###
class TaskViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = TaskSerializer
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter, filters.SearchFilter]
    filterset_fields = ["is_completed", "is_important", "project", "priority", "recurring", "deadline"]
    ordering_fields = ["deadline", "created_at"]
    search_fields = ["title", "description"]

    def get_queryset(self):
        return Task.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        task = serializer.save(user=self.request.user)
        if task.deadline and task.deadline < now():
            raise serializers.ValidationError({"deadline": "Deadline cannot be set in the past."})

    @action(detail=False, methods=["GET"], permission_classes=[IsAuthenticated])
    def progress(self, request):
        total_tasks = Task.objects.filter(user=request.user).count()
        completed_tasks = Task.objects.filter(user=request.user, is_completed=True).count()
        return Response({"completed_tasks": completed_tasks, "total_tasks": total_tasks})


### 🟢 PROJECT VIEWSET ###
class ProjectViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = ProjectSerializer

    def get_queryset(self):
        return Project.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


