"""
Allow running the test suite with plain ``pytest`` by pointing it at the
project's test settings. This is a no-op when the environment already
configures Django (for example through ``DJANGO_SETTINGS_MODULE`` or
``pytest-django``).
"""
import os

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.settings')

try:
    import django
except ImportError:
    django = None

if django is not None:
    django.setup()
