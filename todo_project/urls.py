from django.urls import path, include
from rest_framework.routers import DefaultRouter
from dj_rest_auth.registration.views import SocialLoginView
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from users.views import *
from todos.views import *
from django.contrib import admin
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView



router = DefaultRouter()
router.register(r'tasks', TaskViewSet, basename='task')
router.register(r'categories', ProjectViewSet, basename='project')

class GoogleLogin(SocialLoginView):
    adapter_class = GoogleOAuth2Adapter

urlpatterns = [
    path('api/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/google/validate_token', validate_google_token, name='validate_token'),
    path('accounts/', include('allauth.urls')), 
    path('api-auth/', include('rest_framework.urls')),
    path('api/auth/user', UserDetailView.as_view(), name='user-detail'),
    path('api/', include('todos.urls')),
    path("api/", include("users.urls")),
    path('api/', include(router.urls)),
    path('admin/', admin.site.urls)
] 
