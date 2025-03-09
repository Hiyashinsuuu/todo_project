from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from .models import Category

CustomUser = get_user_model()

@receiver(post_save, sender=CustomUser)
def create_default_categories(sender, instance, created, **kwargs):
    if created:  # Runs only when a new user is created
        categories = ["School", "Work", "Home", "Friends", "Random"]
        for category_name in categories:
            Category.objects.create(user=instance, name=category_name)
