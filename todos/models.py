from django.db import models
from django.contrib.auth import get_user_model


CustomUser = get_user_model()

class Project(models.Model):
    DEFAULT_CHOICES = {
        1: "School",
        2: "Home",
        3: "Random",
        4: "Friends",
    }
    user = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='projects'
    )
    id = models.PositiveSmallIntegerField(primary_key=True)  # ✅ Remove choices
    name = models.CharField(max_length=255, unique=True, null=True, blank=True)

    def __str__(self):
        return self.DEFAULT_CHOICES.get(self.id, "Unknown")  # ✅ Prevent key errors




RECURRING_CHOICES = [
    ('None', 'None'),
    ('Daily', 'Daily'),
    ('Weekly', 'Weekly'),
    ('Monthly', 'Monthly')
]


class Task(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    project = models.ForeignKey(Project, on_delete=models.SET_NULL, null=True, blank=True)
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True, null=True)
    recurring = models.CharField(max_length=10, choices=RECURRING_CHOICES, default='None')
    is_important = models.BooleanField(default=False)
    is_completed = models.BooleanField(default=False)
    deadline = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.title