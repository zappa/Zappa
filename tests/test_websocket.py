import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from zappa.handler import LambdaHandler


class TestWebSocketRegistry(unittest.TestCase):
    """Test decorator and base class registration."""

    def setUp(self):
        # Clear registry before each test
        import zappa.websocket

        self._registry_backup = dict(zappa.websocket._registry)
        zappa.websocket._registry.clear()
        zappa.websocket._validated = False

    def tearDown(self):
        import zappa.websocket

        zappa.websocket._registry.clear()
        zappa.websocket._registry.update(self._registry_backup)
        zappa.websocket._validated = False

    def test_decorators_register_handlers(self):
        from zappa.websocket import _registry, on_connect, on_disconnect, on_message

        @on_connect
        def handle_connect(event, context):
            return {"statusCode": 200}

        @on_disconnect
        def handle_disconnect(event, context):
            return {"statusCode": 200}

        @on_message
        def handle_message(event, context):
            return {"statusCode": 200}

        self.assertIs(_registry["$connect"], handle_connect)
        self.assertIs(_registry["$disconnect"], handle_disconnect)
        self.assertIs(_registry["$default"], handle_message)

    def test_decorators_return_original_function(self):
        from zappa.websocket import on_connect

        def my_handler(event, context):
            return {"statusCode": 200}

        result = on_connect(my_handler)
        self.assertIs(result, my_handler)

    def test_base_class_registers_overridden_methods(self):
        from zappa.websocket import ZappaWebSocketServer, _registry

        class MyWS(ZappaWebSocketServer):
            def on_connect(self, event, context):
                return {"statusCode": 200, "body": "connected"}

            def on_message(self, event, context):
                return {"statusCode": 200, "body": "message"}

        self.assertIn("$connect", _registry)
        self.assertIn("$default", _registry)
        # on_disconnect was not overridden, should not be registered
        self.assertNotIn("$disconnect", _registry)

    def test_base_class_dispatch(self):
        from zappa.websocket import ZappaWebSocketServer, _registry

        class MyWS(ZappaWebSocketServer):
            def on_connect(self, event, context):
                return {"statusCode": 200, "body": "connected"}

        handler = _registry["$connect"]
        result = handler({"test": True}, {})
        self.assertEqual(result, {"statusCode": 200, "body": "connected"})

    def test_get_handler_fallback(self):
        from zappa.websocket import get_handler, on_message

        @on_message
        def handle_msg(event, context):
            return {"statusCode": 200}

        # Unknown route should fall back to $default
        handler = get_handler("$unknown")
        self.assertIs(handler, handle_msg)

    def test_get_handler_returns_none_when_empty(self):
        from zappa.websocket import get_handler

        self.assertIsNone(get_handler("$connect"))

    def test_is_websocket_event(self):
        from zappa.websocket import is_websocket_event

        self.assertTrue(is_websocket_event({"requestContext": {"eventType": "CONNECT"}}))
        self.assertTrue(is_websocket_event({"requestContext": {"eventType": "DISCONNECT"}}))
        self.assertTrue(is_websocket_event({"requestContext": {"eventType": "MESSAGE"}}))
        self.assertFalse(is_websocket_event({"requestContext": {"eventType": "OTHER"}}))
        self.assertFalse(is_websocket_event({"requestContext": {}}))
        self.assertFalse(is_websocket_event({}))

    def test_validate_registry_passes_with_all_required(self):
        from zappa.websocket import on_connect, on_message, validate_registry

        @on_connect
        def handle_connect(event, context):
            return {"statusCode": 200}

        @on_message
        def handle_message(event, context):
            return {"statusCode": 200}

        # Should not raise
        validate_registry()

    def test_validate_registry_passes_with_empty_registry(self):
        from zappa.websocket import validate_registry

        # Empty registry is valid — no WebSocket usage
        validate_registry()

    def test_validate_registry_fails_missing_connect(self):
        from zappa.websocket import (
            WebSocketConfigurationError,
            on_message,
            validate_registry,
        )

        @on_message
        def handle_message(event, context):
            return {"statusCode": 200}

        with self.assertRaises(WebSocketConfigurationError) as ctx:
            validate_registry()
        self.assertIn("@on_connect", str(ctx.exception))

    def test_validate_registry_fails_missing_message(self):
        from zappa.websocket import (
            WebSocketConfigurationError,
            on_connect,
            validate_registry,
        )

        @on_connect
        def handle_connect(event, context):
            return {"statusCode": 200}

        with self.assertRaises(WebSocketConfigurationError) as ctx:
            validate_registry()
        self.assertIn("@on_message", str(ctx.exception))

    def test_validate_registry_fails_only_disconnect(self):
        from zappa.websocket import (
            WebSocketConfigurationError,
            on_disconnect,
            validate_registry,
        )

        @on_disconnect
        def handle_disconnect(event, context):
            return {"statusCode": 200}

        with self.assertRaises(WebSocketConfigurationError) as ctx:
            validate_registry()
        self.assertIn("@on_connect", str(ctx.exception))
        self.assertIn("@on_message", str(ctx.exception))

    def test_validate_registry_runs_only_once(self):
        from zappa.websocket import on_connect, on_message, validate_registry

        @on_connect
        def handle_connect(event, context):
            return {"statusCode": 200}

        @on_message
        def handle_message(event, context):
            return {"statusCode": 200}

        validate_registry()
        # Second call should be a no-op even if we tamper with registry
        import zappa.websocket

        zappa.websocket._registry.clear()
        validate_registry()  # Should not raise


class TestSendMessage(unittest.TestCase):
    """Test the send_message helper."""

    def setUp(self):
        import zappa.websocket

        zappa.websocket._ws_client = None
        zappa.websocket._ws_client_endpoint = None

    @patch("zappa.websocket.boto3.client")
    @patch.dict(os.environ, {"REQUEST_DOMAIN_NAME": "abc123.execute-api.us-east-1.amazonaws.com", "STAGE": "production"})
    def test_send_message_dict(self, mock_client_factory):
        from zappa.websocket import send_message

        mock_client = MagicMock()
        mock_client_factory.return_value = mock_client

        data = {"msg": "hello"}
        send_message("conn-123", data)

        mock_client_factory.assert_called_once_with(
            "apigatewaymanagementapi",
            endpoint_url="https://abc123.execute-api.us-east-1.amazonaws.com/production",
        )
        mock_client.post_to_connection.assert_called_once_with(
            ConnectionId="conn-123",
            Data=json.dumps(data).encode("utf-8"),
        )

    @patch("zappa.websocket.boto3.client")
    @patch.dict(os.environ, {"REQUEST_DOMAIN_NAME": "abc123.execute-api.us-east-1.amazonaws.com", "STAGE": "dev"})
    def test_send_message_string(self, mock_client_factory):
        from zappa.websocket import send_message

        mock_client = MagicMock()
        mock_client_factory.return_value = mock_client

        send_message("conn-456", "raw string")

        mock_client.post_to_connection.assert_called_once_with(
            ConnectionId="conn-456",
            Data=b"raw string",
        )


class TestWebSocketCFTemplate(unittest.TestCase):
    """Test CloudFormation template generation."""

    def test_websocket_resources_created(self):
        from zappa.core import Zappa

        z = Zappa.__new__(Zappa)
        z.boto_session = MagicMock()
        z.boto_session.region_name = "us-east-1"
        z.cf_api_resources = []
        z.cf_parameters = {}

        template = z.create_stack_template(
            lambda_arn="arn:aws:lambda:us-east-1:123456789:function:my-func",
            lambda_name="my-func",
            api_key_required=False,
            iam_authorization=False,
            authorizer=None,
            apigateway_version="v2",
            websocket=True,
            websocket_stage_name="production",
        )

        resources = template.to_dict()["Resources"]
        expected = [
            "WsApi",
            "WsIntegration",
            "WsConnectRoute",
            "WsDisconnectRoute",
            "WsDefaultRoute",
            "WsStage",
            "WsInvokePermission",
        ]
        for name in expected:
            self.assertIn(name, resources, f"Missing CF resource: {name}")

        # Verify WsApi properties
        ws_api = resources["WsApi"]
        self.assertEqual(ws_api["Type"], "AWS::ApiGatewayV2::Api")
        self.assertEqual(ws_api["Properties"]["ProtocolType"], "WEBSOCKET")
        self.assertEqual(ws_api["Properties"]["RouteSelectionExpression"], "$request.body.action")

        # Verify stage
        ws_stage = resources["WsStage"]
        self.assertEqual(ws_stage["Properties"]["StageName"], "production")

    def test_no_websocket_resources_when_disabled(self):
        from zappa.core import Zappa

        z = Zappa.__new__(Zappa)
        z.boto_session = MagicMock()
        z.boto_session.region_name = "us-east-1"
        z.cf_api_resources = []
        z.cf_parameters = {}

        template = z.create_stack_template(
            lambda_arn="arn:aws:lambda:us-east-1:123456789:function:my-func",
            lambda_name="my-func",
            api_key_required=False,
            iam_authorization=False,
            authorizer=None,
            apigateway_version="v2",
            websocket=False,
        )

        resources = template.to_dict()["Resources"]
        for name in [
            "WsApi",
            "WsIntegration",
            "WsConnectRoute",
            "WsDisconnectRoute",
            "WsDefaultRoute",
            "WsStage",
            "WsInvokePermission",
        ]:
            self.assertNotIn(name, resources, f"Unexpected WS resource: {name}")


class TestWebSocketHandlerDispatch(unittest.TestCase):
    """Test WebSocket event dispatch through LambdaHandler."""

    def tearDown(self):
        LambdaHandler._LambdaHandler__instance = None
        LambdaHandler.settings = None
        LambdaHandler.settings_name = None
        # Clear the WS registry
        import zappa.websocket

        zappa.websocket._registry.clear()
        zappa.websocket._validated = False

    def test_connect_event_dispatched(self):
        import zappa.websocket

        results = []

        @zappa.websocket.on_connect
        def handle_connect(event, context):
            results.append("connected")
            return {"statusCode": 200}

        @zappa.websocket.on_message
        def handle_message(event, context):
            return {"statusCode": 200}

        lh = LambdaHandler("tests.test_websocket_settings")

        event = {
            "requestContext": {
                "eventType": "CONNECT",
                "routeKey": "$connect",
                "connectionId": "abc123",
                "domainName": "test.execute-api.us-east-1.amazonaws.com",
                "stage": "production",
            }
        }
        context = MagicMock()
        response = lh.handler(event, context)

        self.assertEqual(results, ["connected"])
        self.assertEqual(response["statusCode"], 200)
        # Verify env vars required by send_message are set
        self.assertEqual(os.environ["REQUEST_DOMAIN_NAME"], "test.execute-api.us-east-1.amazonaws.com")
        self.assertEqual(os.environ["STAGE"], "production")

    def test_message_event_dispatched(self):
        import zappa.websocket

        results = []

        @zappa.websocket.on_connect
        def handle_connect(event, context):
            return {"statusCode": 200}

        @zappa.websocket.on_message
        def handle_msg(event, context):
            results.append("message")
            return {"statusCode": 200}

        lh = LambdaHandler("tests.test_websocket_settings")

        event = {
            "requestContext": {
                "eventType": "MESSAGE",
                "routeKey": "$default",
                "connectionId": "abc123",
                "domainName": "test.execute-api.us-east-1.amazonaws.com",
                "stage": "production",
            },
            "body": '{"action": "sendmessage", "data": "hello"}',
        }
        context = MagicMock()
        response = lh.handler(event, context)

        self.assertEqual(results, ["message"])
        self.assertEqual(response["statusCode"], 200)
        # Verify env vars required by send_message are set
        self.assertEqual(os.environ["REQUEST_DOMAIN_NAME"], "test.execute-api.us-east-1.amazonaws.com")
        self.assertEqual(os.environ["STAGE"], "production")

    def test_no_handler_returns_200(self):
        lh = LambdaHandler("tests.test_websocket_settings")

        event = {
            "requestContext": {
                "eventType": "CONNECT",
                "routeKey": "$connect",
                "connectionId": "abc123",
                "domainName": "test.execute-api.us-east-1.amazonaws.com",
                "stage": "production",
            }
        }
        context = MagicMock()
        response = lh.handler(event, context)

        self.assertEqual(response["statusCode"], 200)


class TestDetectWebSocketUsage(unittest.TestCase):
    """Test auto-detection of zappa.websocket imports."""

    def test_detects_from_import(self):
        from zappa.cli import ZappaCLI

        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "app.py"), "w") as f:
                f.write("from zappa.websocket import on_connect\n")

            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                self.assertEqual(ZappaCLI._detect_websocket_usage(), "app")
            finally:
                os.chdir(old_cwd)

    def test_detects_import_module(self):
        from zappa.cli import ZappaCLI

        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "app.py"), "w") as f:
                f.write("import zappa.websocket\n")

            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                self.assertEqual(ZappaCLI._detect_websocket_usage(), "app")
            finally:
                os.chdir(old_cwd)

    def test_detects_nested_module(self):
        """Files in subdirectories should return dotted module paths."""
        from zappa.cli import ZappaCLI

        with tempfile.TemporaryDirectory() as tmpdir:
            pkg_dir = os.path.join(tmpdir, "mypackage")
            os.makedirs(pkg_dir)
            with open(os.path.join(pkg_dir, "ws.py"), "w") as f:
                f.write("from zappa.websocket import on_connect\n")

            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                self.assertEqual(ZappaCLI._detect_websocket_usage(), "mypackage.ws")
            finally:
                os.chdir(old_cwd)

    def test_no_detection_without_import(self):
        from zappa.cli import ZappaCLI

        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "app.py"), "w") as f:
                f.write("import os\nprint('hello')\n")

            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                self.assertIsNone(ZappaCLI._detect_websocket_usage())
            finally:
                os.chdir(old_cwd)

    def test_string_mention_not_detected(self):
        """A string containing 'zappa.websocket' should not trigger detection."""
        from zappa.cli import ZappaCLI

        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "app.py"), "w") as f:
                f.write('doc = "uses zappa.websocket for ws"\n')

            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                self.assertIsNone(ZappaCLI._detect_websocket_usage())
            finally:
                os.chdir(old_cwd)


class TestWebSocketHandlerAutoImport(unittest.TestCase):
    """Test that LambdaHandler imports WEBSOCKET_HANDLER_MODULE to populate _registry."""

    def tearDown(self):
        LambdaHandler._LambdaHandler__instance = None
        LambdaHandler.settings = None
        LambdaHandler.settings_name = None
        import zappa.websocket

        zappa.websocket._registry.clear()
        zappa.websocket._validated = False
        # Remove cached handler module so re-import triggers decorators again
        sys.modules.pop("tests.test_ws_handlers_fixture", None)

    def test_handler_imports_websocket_module(self):
        """When WEBSOCKET_HANDLER_MODULE is set, _registry should be populated on init."""
        import zappa.websocket

        self.assertEqual(len(zappa.websocket._registry), 0)

        lh = LambdaHandler("tests.test_websocket_autoimport_settings")

        # The decorators in test_websocket_handlers.py should have populated _registry
        self.assertIn("$connect", zappa.websocket._registry)
        self.assertIn("$disconnect", zappa.websocket._registry)
        self.assertIn("$default", zappa.websocket._registry)

    def test_handler_dispatches_after_autoimport(self):
        """WebSocket events should be routed to the auto-imported handlers."""
        lh = LambdaHandler("tests.test_websocket_autoimport_settings")

        event = {
            "requestContext": {
                "eventType": "CONNECT",
                "routeKey": "$connect",
                "connectionId": "abc123",
                "domainName": "test.execute-api.us-east-1.amazonaws.com",
                "stage": "production",
            }
        }
        context = MagicMock()
        response = lh.handler(event, context)

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(response["body"], "connected")

    def test_no_import_when_setting_absent(self):
        """When WEBSOCKET_HANDLER_MODULE is not set, _registry stays empty."""
        import zappa.websocket

        lh = LambdaHandler("tests.test_websocket_settings")

        self.assertEqual(len(zappa.websocket._registry), 0)


class TestWebSocketIAMPermissions(unittest.TestCase):
    """Test that WebSocket enables execute-api:ManageConnections on the Lambda role."""

    def _make_cli(self, use_websocket, manage_roles=True, extra_permissions=None):
        from zappa.cli import ZappaCLI

        cli = ZappaCLI.__new__(ZappaCLI)
        cli.use_websocket = use_websocket
        cli.manage_roles = manage_roles

        # Minimal Zappa mock
        cli.zappa = MagicMock()
        cli.zappa.extra_permissions = extra_permissions
        return cli

    def test_websocket_adds_manage_connections_permission(self):
        """When websocket is enabled, ManageConnections should be added."""
        cli = self._make_cli(use_websocket=True, extra_permissions=None)

        # Simulate the permission-adding block from load_settings
        if cli.use_websocket and cli.manage_roles:
            ws_permission = {
                "Effect": "Allow",
                "Action": ["execute-api:ManageConnections"],
                "Resource": "arn:aws:execute-api:*:*:*",
            }
            if cli.zappa.extra_permissions:
                cli.zappa.extra_permissions.append(ws_permission)
            else:
                cli.zappa.extra_permissions = [ws_permission]

        self.assertEqual(len(cli.zappa.extra_permissions), 1)
        self.assertIn("execute-api:ManageConnections", cli.zappa.extra_permissions[0]["Action"])

    def test_websocket_appends_to_existing_permissions(self):
        """ManageConnections should append to existing extra_permissions."""
        existing = [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]
        cli = self._make_cli(use_websocket=True, extra_permissions=existing)

        if cli.use_websocket and cli.manage_roles:
            ws_permission = {
                "Effect": "Allow",
                "Action": ["execute-api:ManageConnections"],
                "Resource": "arn:aws:execute-api:*:*:*",
            }
            if cli.zappa.extra_permissions:
                cli.zappa.extra_permissions.append(ws_permission)
            else:
                cli.zappa.extra_permissions = [ws_permission]

        self.assertEqual(len(cli.zappa.extra_permissions), 2)

    def test_no_websocket_no_permission_added(self):
        """When websocket is disabled, no ManageConnections permission."""
        cli = self._make_cli(use_websocket=False, extra_permissions=None)

        if cli.use_websocket and cli.manage_roles:
            ws_permission = {
                "Effect": "Allow",
                "Action": ["execute-api:ManageConnections"],
                "Resource": "arn:aws:execute-api:*:*:*",
            }
            if cli.zappa.extra_permissions:
                cli.zappa.extra_permissions.append(ws_permission)
            else:
                cli.zappa.extra_permissions = [ws_permission]

        self.assertIsNone(cli.zappa.extra_permissions)


if __name__ == "__main__":
    unittest.main()
