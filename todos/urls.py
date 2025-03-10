from django.urls import path
from todos.views import progress_tracker, UserSettingsView, dashboard_stats

urlpatterns = [
    path("todos/progress/", progress_tracker, name="progress-tracker"),
    path("settings/", UserSettingsView.as_view(), name="settings"),
    path('user/upload-profile-picture/', UserSettingsView.as_view({'post': 'upload_profile_picture'}), name="upload-profile-picture"),
    path("dashboard/", dashboard_stats, name="dashboard"),
]

