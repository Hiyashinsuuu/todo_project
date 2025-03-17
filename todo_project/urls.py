from django.urls import path, include
from rest_framework.routers import DefaultRouter
from dj_rest_auth.registration.views import SocialLoginView
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from users.views import *
from todos.views import *
from django.contrib import admin
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView



router = DefaultRouter()
router.register(r'tasks', TaskViewSet, basename='task')
router.register(r'categories', ProjectViewSet, basename='project')

class GoogleLogin(SocialLoginView):
    adapter_class = GoogleOAuth2Adapter

urlpatterns = [
    path('api/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/users/register/', RegisterView.as_view(), name='register'),
    path('api/users/login/', UserLoginView.as_view(), name='login'),
    path('api/users/user/', get_user_details, name='get_user_details'),
    path('api/users/google/', GoogleLoginView.as_view(), name='google_login'),
    path('api/google/validate_token', validate_google_token, name='validate_token'),
    path('api/users/password-reset/', PasswordResetView.as_view(), name='password-reset'),
    path('api/users/password-reset-confirm/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('accounts/', include('allauth.urls')), 
    path('api/users/verify-email/<uidb64>/<token>/', VerifyEmailView.as_view(), name='email-verify'),
    path('api/todos/', get_tasks, name='get-tasks'),
    path('api/todos/dashboard/', get_tasks, name='dashboard'),
    path('api/todos/settings/', UserSettingsView.as_view(), name="settings"),
    path('api/todos/create_task/', CreateTaskView.as_view(), name='create-task'),
    path('api/todos/update_task/<int:task_id>/', update_task, name='update-task'),
    path('api/todos/delete_task/<int:task_id>/', delete_task, name='delete-task'),
    path('api/todos/notifications/', task_notifications, name='task-notifications'),
    path('api/todos/progress/', progress_tracker, name='progress-tracker'),
    path('api-auth/', include('rest_framework.urls')),
    path('callback/', google_login_callback, name='callback'),
    path('api/auth/user', UserDetailView.as_view(), name='user-detail'),
    path('api/', include('todos.urls')),
    path("api/", include("users.urls")),
    path('api/', include(router.urls)),
    path('admin/', admin.site.urls)
] 
