from django.apps import AppConfig


class ScansConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.scans'
    verbose_name = 'Security Scans'

    def ready(self):
        """Initialize the scans app"""
        # Import signals or perform initialization here
        pass
