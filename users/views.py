from rest_framework import generics, status
from rest_framework.response import Response
from django.core.mail import send_mail
from django.conf import settings
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse
from rest_framework.parsers import MultiPartParser, FormParser
from .serializers import *
from .models import CustomUser
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.generics import GenericAPIView
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework import serializers
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.permissions import AllowAny, IsAuthenticated
import re
from rest_framework.decorators import api_view, permission_classes
from rest_framework.views import APIView
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from django.utils.deprecation import MiddlewareMixin
from allauth.socialaccount.models import SocialToken, SocialAccount
from django.shortcuts import redirect
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
import datetime
from datetime import timedelta
import requests
from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import authenticate, login


User = get_user_model()



class UserDetailView(generics.RetrieveUpdateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user
    

@login_required
def google_login_callback(request):
    user = request.user

    social_accounts = SocialAccount.objects.filter(user=user)
    print("Social Account for user: ", social_accounts)

    social_account = social_accounts.first()

    if not social_account:
       print("No social account for user: ", user)
       return redirect('http://localhost:8080/login/callback/?error=NoSocialAccount')
    
    token = SocialToken.objects.filter(account=social_account, account__providers='google').first()

    if token:
        print('Google token found: ', token.token)
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        return redirect(f'http://localhost:8080/login/callback/?access_token={access_token}')
    else:
        print('No Google token found for user: ', user)
        return redirect(f'http://localhost:8080/login/callback/?error=NoGoogleToken')
    

class UploadProfilePictureView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request):
        user = request.user
        if 'profile_picture' not in request.FILES:
            return Response({"error": "No image uploaded"}, status=status.HTTP_400_BAD_REQUEST)

        user.profile_picture = request.FILES.get("profile_picture")  # Assign uploaded file
        user.save()  # Save the user instance

        return Response(
            {
                "message": "Profile picture updated successfully",
                "profile_picture": request.build_absolute_uri(user.profile_picture.url)  # Get full URL
            }, 
            status=status.HTTP_200_OK
        )


@csrf_exempt
def validate_google_token(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            google_access_token = data.get('access_token')
            print(google_access_token)

            if not google_access_token:
                return JsonResponse({'detail': 'Access Token is missing'}, status=400)
            return JsonResponse({'valid': True}, status=200)
        except json.JSONDecodeError:
            return JsonResponse({'detail': 'Invalid JSON'}, status=400)
    return JsonResponse({'detail': 'Method not allowed'}, status=405)
    
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_details(request):
    user = request.user
    serializer = CustomUserSerializer(user)
    return Response(serializer.data)

@api_view(['POST', 'PUT', 'PATCH'])
@permission_classes([IsAuthenticated])
def update_user_details(request):
    user = request.user
    serializer = CustomUserSerializer(user, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=400)


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        username_or_email = attrs.get("username")  # Can be username or email
        password = attrs.get("password")

        user = User.objects.filter(username=username_or_email).first() or User.objects.filter(email=username_or_email).first()

        if not user or not user.check_password(password):
            raise serializers.ValidationError("Invalid credentials")

        # Use default validation to generate tokens
        data = super().validate(attrs)
        data["username"] = user.username  # Ensure username is included in response
        return data

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

@api_view(['POST', 'PUT'])
@permission_classes([IsAuthenticated])
def update_user_password(request):
    user = request.user
    serializer = PasswordUpdateSerializer(data=request.data, context={'request': request})
    if serializer.is_valid():
        user.set_password(serializer.validated_data['new_password'])
        user.save()
        return Response({"message": "Password updated successfully"})
    return Response(serializer.errors, status=400)

class RegisterView(generics.CreateAPIView):
    """Register a new user with email confirmation (but already activated and verified)."""
    queryset = CustomUser.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    def validate_password(self, password):
        """Ensure password is at least 8 chars and contains both uppercase & lowercase letters."""
        if len(password) < 8:
            return "Password must be at least 8 characters long."
        if not re.search(r"[a-z]", password) or not re.search(r"[A-Z]", password):
            return "Password must contain both uppercase and lowercase letters."
        return None  

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        user_data = serializer.validated_data
        password = user_data["password"]
        email = user_data.get("email")

        password_error = self.validate_password(password)
        if password_error:
            return Response({"password": [password_error]}, status=status.HTTP_400_BAD_REQUEST)

        if not email:
            return Response({"email": ["Email is required for registration."]}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Create user and set them as active & verified
            user = serializer.create(serializer.validated_data)
            user.is_active = True
            user.is_verified = True
            user.save()

            # Generate email verification link (for confirmation, not activation)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            verification_link = f"https://alisto-main-d4xv.vercel.app/verify-email/{uid}/{token}/"

            # HTML formatted email template
            html_message = f'''
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>AListō Email Confirmation</title>
            </head>
            <body style="margin: 0; padding: 0; font-family: Arial, sans-serif;">
                <div style="background: linear-gradient(to right, #0096FF, #ffffff, #0096FF); padding: 20px 0;">
                    <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 20px;">
                        <div style="text-align: center; margin-bottom: 20px;">
                            <img src="https://i.imgur.com/nSRCAgP.png" alt="AListō" style="max-width: 600px;">
                        </div>
                        
                        <div style="padding: 20px;">
                            <h2 style="color: #0096FF; margin-bottom: 20px;">Hello!</h2>
                            
                            <p style="color: #666666; font-size: 16px; line-height: 1.5;">
                                Your account has been successfully created and verified! 🎉
                            </p>
                            
                            <p style="color: #666666; font-size: 16px; line-height: 1.5;">
                                Click the button below if you’d like to confirm your email address for added security:
                            </p>
                            
                            <div style="text-align: center; margin: 30px 0;">
                                <a href="{verification_link}" style="background-color: #0096FF; color: #ffffff; text-decoration: none; padding: 12px 30px; border-radius: 5px; font-weight: bold;">Confirm Email</a>
                            </div>

                            <p style="color: #666666; font-size: 16px; line-height: 1.5; margin-top: 30px;">Stay productive and rest easy,</p>
                            <p style="color: #0096FF; font-size: 16px; font-weight: bold;">AListō Team</p>
                        </div>
                    </div>
                </div>
            </body>
            </html>
            '''

            plain_text = (
                "Hello!\n\n"
                "Your account has been successfully created and verified! 🎉\n\n"
                "Click the link below if you’d like to confirm your email address for added security:\n"
                f"{verification_link}\n\n"
                "Stay productive and rest easy,\n"
                "AListō Team"
            )

            try:
                from django.core.mail import EmailMultiAlternatives
                import threading
                
                def send_email_task():
                    try:
                        subject = 'Welcome to AListō! Confirm Your Email'
                        from_email = settings.EMAIL_HOST_USER
                        to_email = [email]

                        email_message = EmailMultiAlternatives(subject, plain_text, from_email, to_email)
                        email_message.attach_alternative(html_message, "text/html")
                        email_message.send(fail_silently=False)
                    except Exception as mail_error:
                        print(f"Email sending error: {mail_error}")
                
                email_thread = threading.Thread(target=send_email_task)
                email_thread.daemon = True
                email_thread.start()
            
            except Exception as mail_error:
                print(f"Email thread error: {mail_error}")

            return Response(
                {"message": "Registration successful!"},
                status=status.HTTP_201_CREATED,
            )

        except serializers.ValidationError as ve:
            return Response(ve.detail, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"non_field_errors": [str(e)]}, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmailView(APIView):
    """View to handle email verification and complete user registration."""
    permission_classes = [AllowAny]
    
    def get(self, request, uidb64, token):
        try:
            from django.core.cache import cache
            
            # Get the cached user data
            cache_key = f"unverified_user_{uidb64}_{token}"
            user_cache_data = cache.get(cache_key)
            
            if not user_cache_data:
                print("Cache miss: No data found for key", cache_key)
                return Response(
                    {"error": "Verification link has expired or is invalid. Please register again."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Check if verification token is still valid (within 30 minutes)
            created_at = datetime.datetime.fromisoformat(user_cache_data['created_at'])
            if timezone.now() > created_at + timedelta(minutes=30):
                print("Token expired for user", user_cache_data['user_data'].get('email'))
                cache.delete(cache_key)
                return Response(
                    {"error": "Verification link has expired. Please register again."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Create the user now that email is verified
            user_data = user_cache_data['user_data']
            
            # Check if user already exists (could have been created by another verification attempt)
            existing_user = CustomUser.objects.filter(email=user_data.get('email')).first()
            if existing_user:
                print("User already exists:", existing_user.username)
                # If user exists but is not verified, activate them
                if not existing_user.is_verified or not existing_user.is_active:
                    existing_user.is_active = True
                    existing_user.is_verified = True
                    existing_user.save()
                    cache.delete(cache_key)
                    return Response(
                        {"message": "Email verified successfully. Your account is now active."},
                        status=status.HTTP_200_OK
                    )
                else:
                    cache.delete(cache_key)
                    return Response(
                        {"message": "Your account was already verified. You can now log in."},
                        status=status.HTTP_200_OK
                    )
            
            # Create new user if doesn't exist
            user = CustomUser.objects.create_user(
                username=user_data.get('username'),
                email=user_data.get('email'),
                first_name=user_data.get('first_name', ''),
                last_name=user_data.get('last_name', '')
            )
            
            # Set password and activate user
            user.set_password(user_cache_data['password'])
            user.is_active = True
            user.is_verified = True 
            user.save()
            print("User created and activated:", user.username)

            # Delete the cache entry
            cache.delete(cache_key)
            
            # Return success response
            return Response(
                {"message": "Email verified successfully. Your account is now active."},
                status=status.HTTP_200_OK
            )
            
        except Exception as e:
            print(f"Verification Error: {str(e)}")
            return Response(
                {"error": f"An error occurred during verification: {str(e)}. Please try again."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
class CustomLoginSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)

        if not self.user.is_active:
            raise AuthenticationFailed("Your account is not activated. Please verify your email.")

        data['username'] = self.user.username
        return data
    
CLIENT_ID = "821076926383-mg8nsvmbpe970ibirehbumfopuc9ei0a.apps.googleusercontent.com"

from rest_framework.permissions import AllowAny

class GoogleLoginView(APIView):
    permission_classes = [AllowAny]  # Allow anyone to access this endpoint
    
    def post(self, request):
        google_token = request.data.get("credential")
        
        if not google_token:
            return Response({"error": "Token is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Verify the Google token
            idinfo = id_token.verify_oauth2_token(
                google_token, 
                google_requests.Request(session=requests.Session()), 
                CLIENT_ID,
                clock_skew_in_seconds=10 
            )
            
            # Check issuer
            if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
                return Response({"error": "Wrong issuer"}, status=status.HTTP_401_UNAUTHORIZED)
                
            # Check audience
            if idinfo["aud"] != CLIENT_ID:
                return Response({"error": "Invalid Client ID"}, status=status.HTTP_401_UNAUTHORIZED)
            
            email = idinfo["email"]
            full_name = idinfo.get("name", "")
            profile_picture = idinfo.get("picture", "")
            
            # Get or create user
            user, created = User.objects.get_or_create(email=email, defaults={
                "full_name": full_name,
                "profile_picture": profile_picture or "",
                "is_verified": True,
                "username": email.split("@")[0],  # Use email prefix as username
            })
            
            # Generate tokens
            refresh = RefreshToken.for_user(user)
            return Response({
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "user_exists": not created,
                "user_id": user.id,
                "email": user.email,
                "name": user.full_name,
            }, status=status.HTTP_200_OK)
            
        except ValueError as e:
            print(f"Google Token Verification Failed: {e}")
            return Response({"error": f"Invalid Google token: {str(e)}"}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            print(f"Unexpected error: {e}")
            return Response({"error": f"Authentication error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class CustomHeaderMiddleware(MiddlewareMixin):
    def process_response(self, request, response):
        response['Cross-Origin-Opener-Policy'] = 'same-origin'
        return response

class UserLoginView(TokenObtainPairView):
    serializer_class = CustomLoginSerializer

    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')

        user = CustomUser.objects.filter(username=username).first()
        
        if user := authenticate(request=request, username=username, password=password):
            login(request, user)
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



class PasswordResetView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = PasswordResetSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        
        try:
            user = get_user_model().objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            
            # Create reset link pointing to the frontend route
            frontend_url = "https://alisto-main-d4xv.vercel.app"  # Define this in your settings.py
            reset_link = f"{frontend_url}/reset-password/{uid}/{token}"
            
            # Send email with beautiful HTML template
            html_message = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; }}
                    .email-container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .logo {{ text-align: center; margin-bottom: 20px; }}
                    .header {{ color: #007AFF; font-size: 24px; margin-bottom: 20px; }}
                    .button {{ background-color: #007AFF; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }}
                    .footer {{ margin-top: 40px; color: #666; font-size: 12px; }}
                </style>
            </head>
            <body>
                <div class="email-container">
                    <div class="logo">
                        <img src="https://i.imgur.com/nSRCAgP.png" alt="AListo Logo" style="max-width: 600px;">
                    </div>
                    <h1 class="header">Hello, {user.username}!</h1>
                    <p>We received a request to reset your AListo password.</p>
                    <p>Click <a href="{reset_link}">here</a> to set a new password for your account.</p>
                    <p>If the button above does not work, copy and paste this link into your browser: {reset_link}</p>
                    <p>Didn't request this? No worries—you can safely ignore this email. But if something seems off, consider updating your password to keep your account secure.</p>
                    <p>Stay productive and rest easy,</p>
                    <p>AListo Team</p>
                    <div class="footer" style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #eeeeee;">
                        <img src="https://i.imgur.com/KHu4Nsd.png" alt="AListō" style="max-width: 100px;">
                        <p>Your Plans, Your Moves, AListo Grooves.</p>
                        <p>alisto.adet@gmail.com</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            send_mail(
                'AListo Password Reset',
                f'Click the link to reset your password: {reset_link}',  # Plain text fallback
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False,
                html_message=html_message,  # HTML version of the email
            )
            return Response({'message': 'Password reset email sent.'}, status=status.HTTP_200_OK)
        except get_user_model().DoesNotExist:
            # Return 200 even if email not found for security reasons
            return Response({'message': 'If your email is registered, you will receive a password reset link.'}, 
                           status=status.HTTP_200_OK)


class PasswordResetConfirmView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request, uidb64, token):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        try:
            # Decode the uidb64 to get the user primary key
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = get_user_model().objects.get(pk=uid)
            
            # Validate the token
            if not default_token_generator.check_token(user, token):
                return Response(
                    {'error': 'Password reset link is invalid or has expired.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Set the new password
            user.password = make_password(serializer.validated_data['new_password'])
            user.save()
            
            return Response({'message': 'Password reset successfully'}, status=status.HTTP_200_OK)
        
        except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
            return Response(
                {'error': 'Invalid password reset link.'},
                status=status.HTTP_400_BAD_REQUEST
            )