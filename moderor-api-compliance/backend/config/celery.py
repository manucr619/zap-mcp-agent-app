"""
Celery configuration for Moderor API Compliance Tool.
"""
import os
from celery import Celery
from celery.schedules import crontab

# Set the default Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

# Create Celery app
app = Celery('moderor')

# Load task modules from all registered Django apps
app.autodiscover_tasks()

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes
app.config_from_object('django.conf:settings', namespace='CELERY')

# Configure Celery Beat schedule
app.conf.beat_schedule = {
    'cleanup-old-scans': {
        'task': 'apps.scans.tasks.cleanup_old_scans',
        'schedule': crontab(hour=2, minute=0),  # Run daily at 2 AM
    },
    'update-vulnerability-knowledge-base': {
        'task': 'apps.scans.tasks.update_vulnerability_knowledge_base',
        'schedule': crontab(hour=3, minute=0),  # Run daily at 3 AM
    },
    'generate-weekly-compliance-reports': {
        'task': 'apps.scans.tasks.generate_weekly_compliance_report',
        'schedule': crontab(hour=4, minute=0, day_of_week=1),  # Run weekly on Monday at 4 AM
    },
}

app.conf.timezone = 'UTC'


@app.task(bind=True)
def debug_task(self):
    """Debug task for testing Celery setup"""
    print(f'Request: {self.request!r}')
