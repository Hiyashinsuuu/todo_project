from django.apps import AppConfig


class TodosConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'todos'

    def ready(self):
        pass
        # import todos.signals  # Import the signals when the app is ready
