from typing import Dict, Optional

API_STAGE = "dev"
APP_FUNCTION = "app"
APP_MODULE = "tests.test_wsgi_script_name_app"
BINARY_SUPPORT = False
CONTEXT_HEADER_MAPPINGS: Dict[str, str] = {}
DEBUG = "True"
DJANGO_SETTINGS: Optional[str] = None
DOMAIN = "api.example.com"
ENVIRONMENT_VARIABLES: Dict[str, str] = {}
LOG_LEVEL = "DEBUG"
PROJECT_NAME = "wsgi_script_name_settings"
COGNITO_TRIGGER_MAPPING: Dict[str, str] = {}
AWS_BOT_EVENT_MAPPING: Dict[str, str] = {"intent-name:DialogCodeHook": "tests.test_handler.raises_exception"}
EXCEPTION_HANDLER = "tests.test_handler.mocked_exception_handler"
