from typing import Dict, Optional

API_STAGE = "dev"
APP_FUNCTION = "app"
APP_MODULE = "tests.test_wsgi_binary_support_app"
BINARY_SUPPORT = True
CONTEXT_HEADER_MAPPINGS: Dict[str, str] = {}
DEBUG = "True"
DJANGO_SETTINGS: Optional[str] = None
DOMAIN = "api.example.com"
ENVIRONMENT_VARIABLES: Dict[str, str] = {}
LOG_LEVEL = "DEBUG"
PROJECT_NAME = "binary_support_settings"
COGNITO_TRIGGER_MAPPING: Dict[str, str] = {}
EXCEPTION_HANDLER: Optional[str] = None
