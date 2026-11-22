"""
Pytest bootstrap so the suite can be run directly, e.g.::

    pytest -q tests/test_sessionstore.py tests/test_commands.py tests/test_views.py

When pytest-django is installed it picks up ``DJANGO_SETTINGS_MODULE`` (also
set in ``pyproject.toml``); the ``django.setup()`` call below additionally
covers a plain pytest invocation.
"""
import os

import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.settings')


def pytest_configure(config):  # noqa: ARG001
    django.setup()
