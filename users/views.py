from rest_framework import generics, status
from rest_framework.response import Response
from django.core.mail import send_mail
from django.conf import settings
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, smart_bytes
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse
from .serializers import RegisterSerializer, PasswordResetSerializer, PasswordResetConfirmSerializer, CustomUserSerializer
from .models import CustomUser
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from rest_framework.generics import GenericAPIView
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework import serializers
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
import re
from rest_framework.decorators import api_view, permission_classes



User = get_user_model()
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_details(request):
    user = request.user
    serializer = CustomUserSerializer(user)
    return Response(serializer.data)

@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def update_user_details(request):
    user = request.user
    serializer = CustomUserSerializer(user, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=400)


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)

        # If login fails
        if response.status_code == 401:
            return Response({"detail": "Wrong credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        # If user doesn't exist
        if response.status_code == 404:
            return Response({"detail": "User does not exist"}, status=status.HTTP_404_NOT_FOUND)

        return response
    def validate(self, attrs):
        username_or_email = attrs.get("username")
        password = attrs.get("password")

        user = User.objects.filter(username=username_or_email).first() or User.objects.filter(email=username_or_email).first()

        if user and user.check_password(password):
            return super().validate(attrs)

        raise serializers.ValidationError("Invalid credentials")

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer



class RegisterView(generics.CreateAPIView):
    """Register a new user with email verification and strong password validation."""
    queryset = CustomUser.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    def validate_password(self, password):
        """Ensure password is at least 8 chars and contains both uppercase & lowercase letters."""
        if len(password) < 8:
            return "Password must be at least 8 characters long."
        if not re.search(r"[a-z]", password) or not re.search(r"[A-Z]", password):
            return "Password must contain both uppercase and lowercase letters."
        return None  # ✅ No errors

    def perform_create(self, serializer):
        """Handles user creation with email verification."""
        user_data = serializer.validated_data
        password = user_data["password"]

        # ✅ Validate password
        password_error = self.validate_password(password)
        if password_error:
            raise serializers.ValidationError({"password": [password_error]})

        # ✅ Create user
        user = serializer.save()

        # ✅ Email Verification (if email is provided)
        if user.email:
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            verification_link = self.request.build_absolute_uri(
                reverse('email-verify', kwargs={'uidb64': uid, 'token': token})
            )
            send_mail(
                'Email Verification',
                f'Click the link to verify your email: {verification_link}',
                settings.EMAIL_HOST_USER,
                [user.email],
                fail_silently=False,
            )
            return Response(
                {"message": "User created successfully. Check your email to verify your account."},
                status=status.HTTP_201_CREATED,
            )

        return Response(
            {"message": "User created successfully. No email verification required."},
            status=status.HTTP_201_CREATED,
        )
        
class CustomLoginSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        data['username'] = self.user.username
        return data

class UserLoginView(TokenObtainPairView):
    serializer_class = CustomLoginSerializer

    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')

        user = CustomUser.objects.filter(username=username).first()
        
        if user and user.check_password(password):
            refresh = self.get_serializer().get_token(user)
            return Response({
                "message": "Login successful!",
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "full_name": user.full_name}
            },status=status.HTTP_200_OK)
        return Response({'error': 'Invalid Credentials. Please try again'}, status=401)


class VerifyEmailView(generics.GenericAPIView):
    def get(self, request, uidb64, token):
        try:
            uid = force_bytes(urlsafe_base64_decode(uidb64))
            user = CustomUser.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            user.is_verified = True
            user.is_active = True
            user.save()
            return Response({'message': 'Email verified successfully! You can now log in.'})
        return Response({'message': 'Invalid or expired token.'})

class PasswordResetView(generics.GenericAPIView):
    serializer_class = PasswordResetSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        try:
            user = CustomUser.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            reset_link = request.build_absolute_uri(reverse('password-reset-confirm', kwargs={'uidb64': uid, 'token': token}))
            send_mail(
                'Password Reset',
                f'Click the link to reset your password: {reset_link}',
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False,
            )
            return Response({'message': 'Password reset email sent.'})
        except CustomUser.DoesNotExist:
            return Response({'message': 'Email not found.'})
        
class PasswordResetRequestView(GenericAPIView):
    def post(self, request):
        email = request.data.get('email')
        User = get_user_model()
        try:
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            reset_link = f"http://localhost:8000/api/users/password-reset-confirm/{uid}/{token}/"
            send_mail(
                'Password Reset',
                f'Click the link to reset your password: {reset_link}',
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False,
            )
            return Response({'message': 'Password reset link sent successfully'})
        except User.DoesNotExist:
            return Response({'error': 'User with this email does not exist'}, status=400)

class PasswordResetConfirmView(GenericAPIView):
    def post(self, request, uidb64, token):
        new_password = request.data.get('new_password')
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = get_user_model().objects.get(pk=uid)
            if default_token_generator.check_token(user, token):
                user.password = make_password(new_password)
                user.save()
                return Response({'message': 'Password reset successfully'})
            return Response({'error': 'Invalid token'}, status=400)
        except Exception:
            return Response({'error': 'Invalid request'}, status=400)
        


