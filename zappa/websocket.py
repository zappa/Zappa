"""
WebSocket API Gateway support for Zappa.

Provides decorators, a base class, and helpers for handling
WebSocket connections via API Gateway WebSocket APIs.

Usage with decorators::

    from zappa.websocket import on_connect, on_disconnect, on_message, send_message

    @on_connect
    def handle_connect(event, context):
        return {"statusCode": 200}

    @on_disconnect
    def handle_disconnect(event, context):
        return {"statusCode": 200}

    @on_message
    def handle_message(event, context):
        send_message(event, {"msg": "hello"})
        return {"statusCode": 200}

Usage with base class::

    from zappa.websocket import ZappaWebSocketServer, send_message

    class MyWebSocket(ZappaWebSocketServer):
        def on_connect(self, event, context):
            return {"statusCode": 200}

        def on_message(self, event, context):
            send_message(event, {"echo": event["body"]})
            return {"statusCode": 200}
"""

import json
import logging

import boto3

logger = logging.getLogger(__name__)

# Route key -> callable mapping
_registry = {}
_validated = False

REQUIRED_ROUTES = {"$connect", "$default"}


def on_connect(func):
    """Register a handler for the $connect route."""
    _registry["$connect"] = func
    return func


def on_disconnect(func):
    """Register a handler for the $disconnect route."""
    _registry["$disconnect"] = func
    return func


def on_message(func):
    """Register a handler for the $default route."""
    _registry["$default"] = func
    return func


class ZappaWebSocketServer:
    """Base class for WebSocket handlers.

    Subclass and override on_connect, on_disconnect, and/or on_message.
    Only overridden methods are registered.

    Both ``on_connect`` and ``on_message`` must be overridden (or
    registered via decorators) — ``validate_registry()`` requires
    ``$connect`` and ``$default`` routes whenever any handler is
    registered.  ``on_disconnect`` is optional.
    """

    _instance = None

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        # Register overridden methods at class definition time
        base = ZappaWebSocketServer
        if cls.on_connect is not base.on_connect:
            _registry["$connect"] = cls._dispatch_connect
        if cls.on_disconnect is not base.on_disconnect:
            _registry["$disconnect"] = cls._dispatch_disconnect
        if cls.on_message is not base.on_message:
            _registry["$default"] = cls._dispatch_default
        # Store class ref for lazy instantiation
        cls.__ws_class = cls

    @classmethod
    def _get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def _dispatch_connect(cls, event, context):
        return cls._get_instance().on_connect(event, context)

    @classmethod
    def _dispatch_disconnect(cls, event, context):
        return cls._get_instance().on_disconnect(event, context)

    @classmethod
    def _dispatch_default(cls, event, context):
        return cls._get_instance().on_message(event, context)

    def on_connect(self, event, context):
        return {"statusCode": 200}

    def on_disconnect(self, event, context):
        return {"statusCode": 200}

    def on_message(self, event, context):
        return {"statusCode": 200}


def send_message(event, data):
    """Send a message to a connected WebSocket client.

    Args:
        event: The Lambda event from API Gateway WebSocket.
        data: The data to send (will be JSON-encoded if not a string/bytes).
    """
    request_context = event["requestContext"]
    domain = request_context["domainName"]
    stage = request_context["stage"]
    connection_id = request_context["connectionId"]

    endpoint_url = f"https://{domain}/{stage}"
    client = boto3.client("apigatewaymanagementapi", endpoint_url=endpoint_url)

    if isinstance(data, bytes):
        payload = data
    elif isinstance(data, str):
        payload = data.encode("utf-8")
    else:
        payload = json.dumps(data).encode("utf-8")

    client.post_to_connection(ConnectionId=connection_id, Data=payload)


def validate_registry():
    """Validate that all required routes are registered.

    Raises WebSocketConfigurationError if handlers are registered
    but required routes ($connect, $default) are missing.
    """
    global _validated
    if _validated:
        return
    _validated = True

    if not _registry:
        return

    missing = REQUIRED_ROUTES - set(_registry.keys())
    if missing:
        route_to_decorator = {"$connect": "@on_connect", "$default": "@on_message"}
        missing_names = ", ".join(route_to_decorator.get(r, r) for r in sorted(missing))
        raise WebSocketConfigurationError(
            f"WebSocket handlers registered but missing required routes: {missing_names}. "
            f"All WebSocket apps must define handlers for $connect and $default ($disconnect is optional)."
        )


class WebSocketConfigurationError(Exception):
    """Raised when WebSocket handler registration is incomplete."""


def get_handler(route_key):
    """Get the registered handler for a route key, falling back to $default."""
    return _registry.get(route_key) or _registry.get("$default")


def is_websocket_event(event):
    """Check if an event is a WebSocket API Gateway event."""
    event_type = event.get("requestContext", {}).get("eventType")
    return event_type in ("CONNECT", "DISCONNECT", "MESSAGE")
