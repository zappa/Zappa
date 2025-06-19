from typing import Dict, Optional

API_STAGE = "dev"
APP_FUNCTION = "raises_exception"
APP_MODULE = "tests.test_handler"
BINARY_SUPPORT = False
CONTEXT_HEADER_MAPPINGS: Dict[str, str] = {}
DEBUG = "True"
DJANGO_SETTINGS: Optional[str] = None
DOMAIN = "api.example.com"
ENVIRONMENT_VARIABLES: Dict[str, str] = {}
LOG_LEVEL = "DEBUG"
PROJECT_NAME = "raises_exception"
COGNITO_TRIGGER_MAPPING: Dict[str, str] = {}
EXCEPTION_HANDLER = "tests.test_handler.mocked_exception_handler"
