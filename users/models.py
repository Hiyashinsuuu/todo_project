from django.contrib.auth.models import AbstractUser
from django.db import models

def user_profile_picture_path(instance, filename):
    return f'profile_pictures/{instance.id}/{filename}'  # Saves to 'media/profile_pictures/<user_id>/<filename>'

class CustomUser(AbstractUser):
    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"

    email = models.EmailField(unique=True)
    is_verified = models.BooleanField(default=False)
    profile_picture = models.ImageField(upload_to=user_profile_picture_path, blank=True, null=True)  
    full_name = models.CharField(max_length=255, blank=True, null=True)
    is_active = models.BooleanField(default=True) 
    username = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return self.username
