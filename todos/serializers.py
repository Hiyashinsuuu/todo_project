from rest_framework import serializers
from .models import Task, Category
class TaskSerializer(serializers.ModelSerializer):
    priority = serializers.ChoiceField(choices=[("Low", "Low"), ("High", "High")], default="Low")
    is_important = serializers.BooleanField(default=False)  # Toggle true/false
    user = serializers.HiddenField(default=serializers.CurrentUserDefault())  # Auto-assign logged-in user
    category = serializers.PrimaryKeyRelatedField(queryset=Category.objects.all(), required=False, allow_null=True)

    class Meta:
        model = Task
        fields = [
            "id", "title", "description", "priority", "recurring",
            "is_important", "is_completed", "deadline", "user", "category",
            "created_at", "updated_at"
        ]

    def create(self, validated_data):
        request = self.context.get("request")
        if request and request.user and request.user.is_authenticated:
            validated_data["user"] = request.user
        else:
            raise serializers.ValidationError({"user": "User must be authenticated."})
        
        # Assign "Random" category if no category is provided
        if not validated_data.get("category"):
            validated_data["category"], _ = Category.objects.get_or_create(user=request.user, name="Random")

        return super().create(validated_data)

class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = '__all__'