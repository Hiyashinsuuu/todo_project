from django.contrib import admin
from .models import CustomUser

class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'get_full_name', 'is_active')  

    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}".strip()
    get_full_name.short_description = 'Full Name'

admin.site.register(CustomUser, CustomUserAdmin)
