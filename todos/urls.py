from django.urls import path
from todos.views import progress_tracker, UserSettingsView, DeleteAccountView, dashboard_stats

urlpatterns = [
    path("todos/progress/", progress_tracker, name="progress-tracker"),
    path("settings/", UserSettingsView.as_view(), name="user-settings"),
    path("settings/delete/", DeleteAccountView.as_view(), name="delete-account"),
    path("dashboard/", dashboard_stats, name="dashboard"),
]

