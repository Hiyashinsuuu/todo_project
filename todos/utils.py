from django.utils.timezone import now, timedelta
from .models import Task

def notify_upcoming_tasks(user):
    upcoming_tasks = Task.objects.filter(user=user, deadline__gte=now(), deadline__lte=now() + timedelta(hours=2), is_completed=False)
    return [task.title for task in upcoming_tasks]