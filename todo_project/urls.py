from django.urls import path, include
from rest_framework.routers import DefaultRouter
from dj_rest_auth.registration.views import SocialLoginView
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from users.views import RegisterView, UserLoginView, VerifyEmailView, PasswordResetRequestView, PasswordResetConfirmView
from todos.views import TaskViewSet, CategoryViewSet, progress_tracker
from django.contrib import admin

router = DefaultRouter()
router.register(r'tasks', TaskViewSet, basename='task')
router.register(r'categories', CategoryViewSet, basename='category')

class GoogleLogin(SocialLoginView):
    adapter_class = GoogleOAuth2Adapter

urlpatterns = [
    path('api/users/register/', RegisterView.as_view(), name='register'),
    path('api/users/login/', UserLoginView.as_view(), name='login'),
    # path('api/users/google/', GoogleLogin.as_view(), name='google_login'),
    path('accounts/', include('allauth.urls')), 
    path('api/users/verify-email/<uidb64>/<token>/', VerifyEmailView.as_view(), name='email-verify'),
    path('api/users/password-reset/', PasswordResetRequestView.as_view(), name='password-reset'),
    path('api/users/password-reset-confirm/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('api/todos/progress/', progress_tracker, name='progress-tracker'),
    path('api/', include('todos.urls')),
    path('api/', include(router.urls)),
    path('admin/', admin.site.urls)
]
