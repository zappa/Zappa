import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple

from .utilities import extract_request_body, resolve_context_headers
from .wsgi import process_lambda_payload_v1, process_lambda_payload_v2

logger = logging.getLogger(__name__)


def create_asgi_scope(
    event_info: Dict[str, Any],
    server_name: str = "zappa",
    script_name: Optional[str] = None,
    trailing_slash: bool = True,
    binary_support: bool = False,
    base_path: Optional[str] = None,
    context_header_mappings: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Given an event_info from API Gateway or Function URL,
    create and return a valid ASGI scope dict.
    """
    if event_info.get("version", "") == "2.0":
        method, headers, path, query_string, remote_user, authorizer = process_lambda_payload_v2(event_info)
    else:
        method, headers, path, query_string, remote_user, authorizer = process_lambda_payload_v1(event_info)

    resolve_context_headers(event_info, headers, context_header_mappings)

    if base_path:
        script_name = f"/{base_path}"
        if path.startswith(script_name):
            path = path[len(script_name) :]

    # Strip stage prefix from path if script_name is set
    if script_name and path.startswith(script_name):
        path = path[len(script_name) :]

    if trailing_slash and not path.endswith("/"):
        path = path + "/"

    # Normalize header keys to lowercase for consistent lookups
    lower_headers = {k.lower(): v for k, v in headers.items()}

    # Determine client from X-Forwarded-For
    x_forwarded_for = lower_headers.get("x-forwarded-for", "")
    if "," in x_forwarded_for:
        addresses = [addr.strip() for addr in x_forwarded_for.split(",")]
        remote_addr = addresses[-2]
    else:
        remote_addr = x_forwarded_for or "127.0.0.1"

    # Determine server
    host = lower_headers.get("host", server_name)
    port_header = lower_headers.get("x-forwarded-port", "443")
    try:
        port = int(port_header)
    except (TypeError, ValueError):
        port = 443

    # Build ASGI headers as list of [name, value] byte pairs
    asgi_headers: List[Tuple[bytes, bytes]] = [
        (k.encode("latin-1"), str(v).encode("latin-1")) for k, v in lower_headers.items()
    ]

    scope: Dict[str, Any] = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "path": path or "/",
        "root_path": script_name or "",
        "scheme": "https",
        "query_string": query_string.encode("latin-1") if query_string else b"",
        "headers": asgi_headers,
        "server": (host, port),
        "client": (remote_addr, 0),
    }

    if authorizer:
        scope["authorizer"] = authorizer
    if remote_user:
        scope["remote_user"] = remote_user

    return scope


def create_asgi_request_body(
    event_info: Dict[str, Any],
    binary_support: bool = False,
) -> bytes:
    """
    Extract the request body from a Lambda event as bytes.
    Handles base64 decoding when isBase64Encoded is True.
    """
    method = event_info.get("httpMethod") or (event_info.get("requestContext", {}).get("http", {}).get("method", "GET"))
    return extract_request_body(event_info, method, binary_support)


class ASGIHandler:
    """
    Bridges synchronous Lambda invocation to an async ASGI application.

    Collects the response status, headers, and body from ASGI send() calls.
    """

    def __init__(self, app: Any, scope: Dict[str, Any], body: bytes) -> None:
        self.app = app
        self.scope = scope
        self.body = body
        self.status_code: int = 200
        self.response_headers: List[Tuple[bytes, bytes]] = []
        self.response_body = bytearray()
        self._request_sent = False

    async def receive(self) -> Dict[str, Any]:
        if not self._request_sent:
            self._request_sent = True
            return {
                "type": "http.request",
                "body": self.body,
                "more_body": False,
            }
        # After the request is sent, signal disconnect immediately.
        # In Lambda there is no persistent connection, so blocking here
        # would hang the invocation until timeout.
        return {"type": "http.disconnect"}

    async def send(self, message: Dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            self.status_code = message["status"]
            self.response_headers = message.get("headers", [])
        elif message["type"] == "http.response.body":
            body = message.get("body", b"")
            if body:
                self.response_body.extend(body)

    def run(self) -> None:
        """Run the ASGI app synchronously using the event loop."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is None or loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        loop.run_until_complete(self.app(self.scope, self.receive, self.send))
