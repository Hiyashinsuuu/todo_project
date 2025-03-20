from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from .models import Task

CustomUser = get_user_model()



@receiver(post_save, sender=CustomUser)
def create_default_task(sender, instance, created, **kwargs):
    if created:  # Only create a task when a user is first registered
        Task.objects.create(
            user=instance,
            title="Welcome Task",
            description="This is your first task!",
        )