from django.urls import path
from .views import RegisterView, VerifyEmailView,  UserLoginView, get_user_details, update_user_details

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('verify-email/<uidb64>/<token>/', VerifyEmailView.as_view(), name='email-verify'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('user/', get_user_details, name='get_user_details'),
    path('user/update/', update_user_details, name='update_user_details'),
]