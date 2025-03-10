from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    is_verified = models.BooleanField(default=False)
    profile_picture = models.ImageField(upload_to='profile_pics/', blank=True, null=True, default='default_profile.jpg')
    full_name = models.CharField(max_length=255, blank=True, null=True)
    is_active = models.BooleanField(default=True) 
    username = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return self.username