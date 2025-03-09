from django.urls import path
from todos.views import progress_tracker

urlpatterns = [
    path("todos/progress/", progress_tracker, name="progress-tracker"),
]
