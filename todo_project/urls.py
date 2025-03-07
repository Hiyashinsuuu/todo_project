from django.urls import path, include
from rest_framework.routers import DefaultRouter
from users.views import RegisterView, LoginView, VerifyEmailView, PasswordResetRequestView, PasswordResetConfirmView
from todos.views import TaskViewSet, CategoryViewSet, inbox_tasks, progress_tracker

router = DefaultRouter()
router.register(r'tasks', TaskViewSet, basename='task')
router.register(r'categories', CategoryViewSet, basename='category')

urlpatterns = [
    path('api/users/register/', RegisterView.as_view(), name='register'),
    path('api/users/login/', LoginView.as_view(), name='login'),
    path('api/users/verify-email/<uidb64>/<token>/', VerifyEmailView.as_view(), name='email-verify'),
    path('api/users/password-reset/', PasswordResetRequestView.as_view(), name='password-reset'),
    path('api/users/password-reset-confirm/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('api/todos/inbox/', inbox_tasks, name='inbox-tasks'),
    path('api/todos/progress/', progress_tracker, name='progress-tracker'),
    path('api/', include(router.urls)),
]
