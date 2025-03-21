from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from .models import CustomUser
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.conf import settings
from django.core.exceptions import ValidationError
from .models import CustomUser  

class CustomUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False)
    
    class Meta:
        model = CustomUser
        fields = ['username', 'profile_picture', 'password']
    
    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
     
        if password is not None:
            instance.set_password(password)
        
        instance.save()
        return instance
    

class RegisterSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ["full_name", "username", "email", "password", "confirm_password"]
        extra_kwargs = {"password": {"write_only": True}}

    def validate(self, data):
        """Ensure passwords match and follow security rules."""
        if data["password"] != data["confirm_password"]:
            raise serializers.ValidationError({"password": ["Passwords do not match."]})

        try:
            validate_password(data["password"]) 
        except ValidationError as e:
            raise serializers.ValidationError({"password": e.messages})

        return data

    def create(self, validated_data):
        """Create user and handle additional fields."""
        validated_data.pop("confirm_password") 
        full_name = validated_data.pop("full_name", "")
        name_parts = full_name.split()
        validated_data["first_name"] = name_parts[0] if name_parts else ""
        validated_data["last_name"] = " ".join(name_parts[1:]) if len(name_parts) > 1 else ""

        try:
            user = CustomUser.objects.create_user(**validated_data)
            user.is_active = False
            user.save()
            return user
        except Exception as e:
            raise serializers.ValidationError({"error": str(e)}) # ✅ Ensure user is returned


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

class PasswordResetConfirmSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True, required=True)

    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError({'confirm_password': "Passwords do not match."})
        return attrs
    