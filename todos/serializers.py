from django.utils import timezone 
from rest_framework import serializers
from .models import *
from django.contrib.auth import get_user_model

User = get_user_model()

class TaskSerializer(serializers.ModelSerializer):
    project = serializers.PrimaryKeyRelatedField(
        queryset=Project.objects.all(), required=False, allow_null=True
    ) 

    class Meta:
        model = Task
        fields = [
            "id", "title", "description", "recurring",
            "is_important", "is_completed", "deadline", "user", "project",
            "created_at", "updated_at"
        ]

    def validate(self, data):
        if not data.get("title"):
            raise serializers.ValidationError({"title": "Title is required."})
        if data.get("deadline") and data["deadline"] < timezone.now():
            raise serializers.ValidationError({"deadline": "Deadline cannot be in the past."})
        return data



class ProjectSerializer(serializers.ModelSerializer):
    name = serializers.SerializerMethodField()

    class Meta:
        model = Project
        fields = ["id", "name"]

    def get_name(self, obj):
        return Project.DEFAULT_CHOICES[obj.id]


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