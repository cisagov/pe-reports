# __init__.py

from .celery_config import app as celery_app

__all__ = ('celery_app',)