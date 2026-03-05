import base64
import json
import unittest

from zappa.handler import LambdaHandler

from .utils import is_base64


class TestASGI(unittest.TestCase):
    def setUp(self):
        LambdaHandler._LambdaHandler__instance = None
        LambdaHandler.settings = None
        LambdaHandler.settings_name = None

    def tearDown(self):
        LambdaHandler._LambdaHandler__instance = None
        LambdaHandler.settings = None
        LambdaHandler.settings_name = None

    def test_asgi_v2_function_url(self):
        """Ensure ASGI apps handle v2 Function URL events (no stage)."""
        lh = LambdaHandler("tests.test_asgi_settings")

        event = {
            "version": "2.0",
            "routeKey": "$default",
            "rawPath": "/return/request/url",
            "rawQueryString": "",
            "headers": {
                "host": "1234567890.lambda-url.us-east-1.on.aws",
            },
            "requestContext": {
                "http": {
                    "method": "GET",
                    "path": "/return/request/url",
                },
            },
            "isBase64Encoded": False,
            "body": "",
        }
        response = lh.handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        self.assertIn("/return/request/url", response["body"])
        self.assertIn("https://", response["body"])

    def test_asgi_v2_with_stage_prefix(self):
        """Ensure ASGI apps strip stage prefix from PATH for v2 API Gateway events."""
        lh = LambdaHandler("tests.test_asgi_settings")

        event = {
            "version": "2.0",
            "routeKey": "$default",
            "rawPath": "/dev/return/request/url",
            "rawQueryString": "",
            "headers": {
                "host": "1234567890.execute-api.us-east-1.amazonaws.com",
            },
            "requestContext": {
                "http": {
                    "method": "GET",
                    "path": "/dev/return/request/url",
                },
                "stage": "dev",
            },
            "isBase64Encoded": False,
            "body": "",
        }
        response = lh.handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        # The URL should include the stage prefix via root_path
        self.assertIn("/dev/return/request/url", response["body"])

    def test_asgi_v1_basic(self):
        """Ensure ASGI apps handle v1 API Gateway events."""
        lh = LambdaHandler("tests.test_asgi_settings")

        event = {
            "body": "",
            "resource": "/{proxy+}",
            "requestContext": {},
            "queryStringParameters": {},
            "headers": {
                "Host": "example.com",
            },
            "pathParameters": {"proxy": "return/request/url"},
            "httpMethod": "GET",
            "stageVariables": {},
            "path": "/return/request/url",
        }
        response = lh.handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        self.assertIn("/return/request/url", response["body"])

    def test_asgi_v1_alb(self):
        """Ensure ASGI apps handle ALB events with statusDescription."""
        lh = LambdaHandler("tests.test_asgi_settings")

        event = {
            "requestContext": {
                "elb": {
                    "targetGroupArn": "arn:aws:elasticloadbalancing:region:123456789012:targetgroup/my-tg/6d0ecf831eec9f09"
                }
            },
            "httpMethod": "GET",
            "path": "/json",
            "queryStringParameters": {},
            "headers": {
                "host": "1234567890.execute-api.us-east-1.amazonaws.com",
            },
            "isBase64Encoded": False,
            "body": "",
        }
        response = lh.handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(response["statusDescription"], "200 OK")
        self.assertIn("isBase64Encoded", response)

    def test_asgi_v1_multi_value_headers(self):
        """Ensure ASGI apps return multiValueHeaders when event has them."""
        lh = LambdaHandler("tests.test_asgi_settings")

        event = {
            "body": "",
            "resource": "/{proxy+}",
            "requestContext": {},
            "queryStringParameters": {},
            "multiValueHeaders": {
                "Host": ["example.com"],
            },
            "pathParameters": {"proxy": "set-cookies"},
            "httpMethod": "GET",
            "stageVariables": {},
            "path": "/set-cookies",
        }
        response = lh.handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        self.assertIn("multiValueHeaders", response)
        # Should have multiple set-cookie values
        set_cookie_values = response["multiValueHeaders"].get("set-cookie", [])
        self.assertEqual(len(set_cookie_values), 2)

    def test_asgi_v2_cookies(self):
        """Ensure ASGI v2 responses return cookies in the cookies list."""
        lh = LambdaHandler("tests.test_asgi_settings")

        event = {
            "version": "2.0",
            "routeKey": "$default",
            "rawPath": "/set-cookies",
            "rawQueryString": "",
            "headers": {
                "host": "example.com",
            },
            "requestContext": {
                "http": {
                    "method": "GET",
                    "path": "/set-cookies",
                },
            },
            "isBase64Encoded": False,
            "body": "",
        }
        response = lh.handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(len(response["cookies"]), 2)
        self.assertTrue(any("session=abc123" in c for c in response["cookies"]))
        self.assertTrue(any("theme=dark" in c for c in response["cookies"]))

    def test_asgi_binary_support_gzip(self):
        """Ensure gzip Content-Encoding response is base64 encoded when BINARY_SUPPORT is True."""
        lh = LambdaHandler("tests.test_asgi_binary_support_settings")

        event = {
            "version": "2.0",
            "routeKey": "$default",
            "rawPath": "/gzip",
            "rawQueryString": "",
            "headers": {
                "host": "example.com",
            },
            "requestContext": {
                "http": {
                    "method": "GET",
                    "path": "/gzip",
                },
            },
            "isBase64Encoded": False,
            "body": "",
        }
        response = lh.handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        self.assertTrue(response["isBase64Encoded"])
        self.assertTrue(is_base64(response["body"]))

    def test_asgi_binary_support_binary(self):
        """Ensure binary mimetype response is base64 encoded when BINARY_SUPPORT is True."""
        lh = LambdaHandler("tests.test_asgi_binary_support_settings")

        event = {
            "version": "2.0",
            "routeKey": "$default",
            "rawPath": "/binary",
            "rawQueryString": "",
            "headers": {
                "host": "example.com",
            },
            "requestContext": {
                "http": {
                    "method": "GET",
                    "path": "/binary",
                },
            },
            "isBase64Encoded": False,
            "body": "",
        }
        response = lh.handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        self.assertTrue(response["isBase64Encoded"])
        self.assertTrue(is_base64(response["body"]))

    def test_asgi_binary_support_text_not_encoded(self):
        """Ensure text/* mimetype response is NOT base64 encoded even with BINARY_SUPPORT."""
        lh = LambdaHandler("tests.test_asgi_binary_support_settings")

        event = {
            "version": "2.0",
            "routeKey": "$default",
            "rawPath": "/return/request/url",
            "rawQueryString": "",
            "headers": {
                "host": "example.com",
            },
            "requestContext": {
                "http": {
                    "method": "GET",
                    "path": "/return/request/url",
                },
            },
            "isBase64Encoded": False,
            "body": "",
        }
        response = lh.handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        self.assertFalse(response["isBase64Encoded"])

    def test_asgi_binary_support_json_not_encoded(self):
        """Ensure application/json response is NOT base64 encoded even with BINARY_SUPPORT."""
        lh = LambdaHandler("tests.test_asgi_binary_support_settings")

        event = {
            "version": "2.0",
            "routeKey": "$default",
            "rawPath": "/json",
            "rawQueryString": "",
            "headers": {
                "host": "example.com",
            },
            "requestContext": {
                "http": {
                    "method": "GET",
                    "path": "/json",
                },
            },
            "isBase64Encoded": False,
            "body": "",
        }
        response = lh.handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        self.assertFalse(response["isBase64Encoded"])
        data = json.loads(response["body"])
        self.assertEqual(data["message"], "hello")

    def test_asgi_post_with_body(self):
        """Ensure ASGI apps receive POST body correctly."""
        lh = LambdaHandler("tests.test_asgi_settings")

        event = {
            "version": "2.0",
            "routeKey": "$default",
            "rawPath": "/echo-body",
            "rawQueryString": "",
            "headers": {
                "host": "example.com",
                "content-type": "text/plain",
            },
            "requestContext": {
                "http": {
                    "method": "POST",
                    "path": "/echo-body",
                },
            },
            "isBase64Encoded": False,
            "body": "hello world",
        }
        response = lh.handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(response["body"], "hello world")

    def test_asgi_post_with_base64_body(self):
        """Ensure ASGI apps decode base64 bodies when isBase64Encoded is True."""
        lh = LambdaHandler("tests.test_asgi_binary_support_settings")

        original_body = "hello binary world"
        encoded_body = base64.b64encode(original_body.encode("utf-8")).decode("utf-8")

        event = {
            "version": "2.0",
            "routeKey": "$default",
            "rawPath": "/echo-body",
            "rawQueryString": "",
            "headers": {
                "host": "example.com",
                "content-type": "text/plain",
            },
            "requestContext": {
                "http": {
                    "method": "POST",
                    "path": "/echo-body",
                },
            },
            "isBase64Encoded": True,
            "body": encoded_body,
        }
        response = lh.handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(response["body"], original_body)

    def test_asgi_autodetect(self):
        """Ensure auto-detection identifies async callable as ASGI app."""
        lh = LambdaHandler("tests.test_asgi_autodetect_settings")

        self.assertEqual(lh.app_type, "asgi")
        self.assertIsNotNone(lh.asgi_app)
        self.assertIsNone(lh.wsgi_app)

        event = {
            "version": "2.0",
            "routeKey": "$default",
            "rawPath": "/json",
            "rawQueryString": "",
            "headers": {
                "host": "example.com",
            },
            "requestContext": {
                "http": {
                    "method": "GET",
                    "path": "/json",
                },
            },
            "isBase64Encoded": False,
            "body": "",
        }
        response = lh.handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        data = json.loads(response["body"])
        self.assertEqual(data["message"], "hello")

    def test_wsgi_backward_compatibility(self):
        """Ensure Flask (WSGI) apps still work correctly and are NOT detected as ASGI."""
        lh = LambdaHandler("tests.test_wsgi_script_name_settings")

        self.assertIsNone(lh.app_type)
        self.assertIsNotNone(lh.wsgi_app)
        self.assertIsNone(lh.asgi_app)

        event = {
            "body": "",
            "resource": "/{proxy+}",
            "requestContext": {},
            "queryStringParameters": {},
            "headers": {
                "Host": "example.com",
            },
            "pathParameters": {"proxy": "return/request/url"},
            "httpMethod": "GET",
            "stageVariables": {},
            "path": "/return/request/url",
        }
        response = lh.handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(response["body"], "https://example.com/return/request/url")

    def test_asgi_v1_with_query_string(self):
        """Ensure ASGI apps handle query strings correctly."""
        lh = LambdaHandler("tests.test_asgi_settings")

        event = {
            "body": "",
            "resource": "/{proxy+}",
            "requestContext": {},
            "queryStringParameters": {"foo": "bar", "baz": "qux"},
            "headers": {
                "Host": "example.com",
            },
            "pathParameters": {"proxy": "return/request/url"},
            "httpMethod": "GET",
            "stageVariables": {},
            "path": "/return/request/url",
        }
        response = lh.handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        self.assertIn("foo=bar", response["body"])
        self.assertIn("baz=qux", response["body"])

    def test_asgi_404(self):
        """Ensure ASGI app returns 404 for unknown routes."""
        lh = LambdaHandler("tests.test_asgi_settings")

        event = {
            "version": "2.0",
            "routeKey": "$default",
            "rawPath": "/nonexistent",
            "rawQueryString": "",
            "headers": {
                "host": "example.com",
            },
            "requestContext": {
                "http": {
                    "method": "GET",
                    "path": "/nonexistent",
                },
            },
            "isBase64Encoded": False,
            "body": "",
        }
        response = lh.handler(event, None)

        self.assertEqual(response["statusCode"], 404)

    def test_is_asgi_app_detection(self):
        """Test the _is_asgi_app static method directly."""

        # Async function with 3 params → ASGI
        async def asgi_app(scope, receive, send):
            pass

        self.assertTrue(LambdaHandler._is_asgi_app(asgi_app))

        # Async function with 2 params → not ASGI
        async def not_asgi(scope, receive):
            pass

        self.assertFalse(LambdaHandler._is_asgi_app(not_asgi))

        # Sync function with 3 params → not ASGI
        def sync_app(scope, receive, send):
            pass

        self.assertFalse(LambdaHandler._is_asgi_app(sync_app))

        # Non-callable → not ASGI
        self.assertFalse(LambdaHandler._is_asgi_app("not a callable"))

        # Class with async __call__ and 3 params → ASGI
        class AsyncCallable:
            async def __call__(self, scope, receive, send):
                pass

        self.assertTrue(LambdaHandler._is_asgi_app(AsyncCallable()))

    def test_asgi_v1_binary_support_gzip(self):
        """Ensure v1 ASGI handler handles gzip binary support."""
        lh = LambdaHandler("tests.test_asgi_binary_support_settings")

        event = {
            "body": "",
            "resource": "/{proxy+}",
            "requestContext": {},
            "queryStringParameters": {},
            "headers": {
                "Host": "example.com",
            },
            "pathParameters": {"proxy": "gzip"},
            "httpMethod": "GET",
            "stageVariables": {},
            "path": "/gzip",
        }
        response = lh.handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        self.assertIn("isBase64Encoded", response)
        self.assertTrue(response["isBase64Encoded"])
        self.assertTrue(is_base64(response["body"]))
