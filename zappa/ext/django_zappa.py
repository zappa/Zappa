import os
import sys

# add the Lambda root path into the sys.path
sys.path.append("/var/task")


def get_django_wsgi(settings_module):
    from django.core.wsgi import get_wsgi_application

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", settings_module)

    return get_wsgi_application()
