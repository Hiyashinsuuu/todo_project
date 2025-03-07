from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from .models import CustomUser
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.conf import settings

class RegisterSerializer(serializers.ModelSerializer):
    full_name = serializers.CharField(required=True)
    email = serializers.EmailField(required=False)
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'password', 'confirm_password', 'full_name']

    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({'confirm_password': "Password fields didn't match."})
        return attrs

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        full_name = validated_data.pop('full_name')
        name_parts = full_name.split()
        validated_data['first_name'] = name_parts[0]
        validated_data['last_name'] = ' '.join(name_parts[1:]) if len(name_parts) > 1 else ''
        user = CustomUser.objects.create_user(**validated_data)
        user.is_active = False if validated_data.get('email') else True
        user.save()

        if validated_data.get('email'):
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            verification_link = f"http://localhost:8000/api/users/verify-email/{uid}/{token}/"
            send_mail(
                'Email Verification',
                f'Click the link to verify your email: {verification_link}',
                settings.EMAIL_HOST_USER,
                [validated_data['email']],
                fail_silently=False,
            )

        return user

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

class PasswordResetConfirmSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True, required=True)

    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError({'confirm_password': "Passwords do not match."})
        return attrs