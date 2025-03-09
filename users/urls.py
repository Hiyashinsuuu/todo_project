from django.urls import path
from .views import RegisterView, VerifyEmailView,  UserLoginView, get_tasks, create_task, update_task, delete_task

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('verify-email/<uidb64>/<token>/', VerifyEmailView.as_view(), name='email-verify'),
    path('login/', UserLoginView.as_view(), name='login'),
]