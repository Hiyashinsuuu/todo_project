from django.urls import path
from .views import *


urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('verify-email/<uidb64>/<token>/', VerifyEmailView.as_view(), name='email-verify'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('user/', get_user_details, name='get_user_details'),
    path('update-password/', update_user_password, name='update_user_password'),
    path('update/', update_user_details, name='update_user_details'),
    path("google/", GoogleLoginView.as_view(), name="google_login"),
    path('user/upload-profile-picture/', UploadProfilePictureView.as_view(), name='upload-profile-picture'),
    path('password-reset/<uidb64>/<token>/', PasswordResetView.as_view(), name='password-reset'),
    path('password-reset-confirm/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
]