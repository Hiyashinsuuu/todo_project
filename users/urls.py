from django.urls import path
from .views import RegisterView, VerifyEmailView, LoginView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('verify-email/<uidb64>/<token>/', VerifyEmailView.as_view(), name='email-verify'),
    path('login/', LoginView.as_view(), name='login'),
]