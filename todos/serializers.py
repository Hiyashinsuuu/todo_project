from rest_framework import serializers
from .models import Task, Project
from django.contrib.auth import get_user_model

User = get_user_model()

class TaskSerializer(serializers.ModelSerializer):
    priority = serializers.ChoiceField(choices=[("Low", "Low"), ("High", "High")], default="Low")
    is_important = serializers.BooleanField(default=False)  # Toggle true/false
    user = serializers.HiddenField(default=serializers.CurrentUserDefault())  # Auto-assign logged-in user
    project = serializers.PrimaryKeyRelatedField(queryset=Project.objects.all(), required=False, allow_null=True)
    description = serializers.CharField(required=False, allow_blank=True) 

    class Meta:
        model = Task
        fields = [
            "id", "title", "description", "priority", "recurring",
            "is_important", "is_completed", "deadline", "user", "project",
            "created_at", "updated_at"
        ]

        def validate_title(self, value):
            """ Ensure title is not empty """
            if not value.strip():
                raise serializers.ValidationError("Title is required.")
            return value

        def create(self, validated_data):
            request = self.context.get("request")
            if request and request.user and request.user.is_authenticated:
                validated_data["user"] = request.user
            else:
                raise serializers.ValidationError({"user": "User must be authenticated."})
            
            # Assign "Random" project if no project is provided
            if not validated_data.get("project"):
                validated_data["project"], _ = Project.objects.get_or_create(user=request.user, name="Random")

            return super().create(validated_data)

class ProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Project
        fields = '__all__'

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