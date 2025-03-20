from django.utils import timezone 
from rest_framework import serializers
from .models import *
from django.contrib.auth import get_user_model

User = get_user_model()

class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = [
            "id", "title", "description", "recurring",
            "is_important", "is_completed", "deadline", "user",
            "created_at", "updated_at"
        ]
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        user = None
        if 'request' in self.context:
            user = self.context['request'].user
        elif 'user' in self.context:
            user = self.context['user']
        
        if user and not user.is_anonymous:
            # Log the user
            print(f"Serializer initialized with user: {user.id}")
        else:
            print("No user found in context or user is anonymous")


class SettingsSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False)
    profile_picture = serializers.ImageField(required=False)

    class Meta:
        model = User
        fields = ["username", "password", "profile_picture"]

    def update(self, instance, validated_data):
        # Update username
        instance.username = validated_data.get("username", instance.username)

        # Update password if provided
        password = validated_data.get("password")
        if password:
            instance.set_password(password)  # Hash the new password

        # Update profile picture
        profile_picture = validated_data.get("profile_picture")
        if profile_picture:
            instance.profile_picture = profile_picture

        instance.save()
        return instance