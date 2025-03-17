from django.urls import path
from todos.views import *

urlpatterns = [
    path("todos/progress/", progress_tracker, name="progress-tracker"),
    path("settings/", UserSettingsView.as_view(), name="settings"),
    path('user/upload-profile-picture/', UploadProfilePictureView.as_view(), name="upload-profile-picture"),
    path("dashboard/", dashboard_stats, name="dashboard"),
    
]

