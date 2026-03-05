"""
Pure ASGI test application — no framework dependencies.

Routes:
  /return/request/url — Returns the reconstructed request URL
  /json               — Returns JSON response
  /set-cookies        — Returns multiple Set-Cookie headers
  /binary             — Returns binary data with arbitrary mimetype
  /gzip               — Returns gzip-compressed response with Content-Encoding
  /echo-body          — Echoes back the request body
  *                   — 404 Not Found
"""

import gzip
import json
from typing import Any, Callable, Dict, List, Tuple


async def app(scope: Dict[str, Any], receive: Callable, send: Callable) -> None:
    """Pure ASGI application for testing."""
    assert scope["type"] == "http"

    path = scope.get("path", "/")
    method = scope.get("method", "GET")

    # Read request body
    body = b""
    while True:
        message = await receive()
        body += message.get("body", b"")
        if not message.get("more_body", False):
            break

    if path.rstrip("/") == "/return/request/url":
        await _handle_return_request_url(scope, send)
    elif path.rstrip("/") == "/json":
        await _handle_json(scope, send)
    elif path.rstrip("/") == "/set-cookies":
        await _handle_set_cookies(scope, send)
    elif path.rstrip("/") == "/binary":
        await _handle_binary(scope, send)
    elif path.rstrip("/") == "/gzip":
        await _handle_gzip(scope, send)
    elif path.rstrip("/") == "/echo-body":
        await _handle_echo_body(scope, send, body)
    else:
        await _handle_not_found(scope, send)


def _get_header(headers: List[Tuple[bytes, bytes]], name: str) -> str:
    """Get a header value from ASGI headers list."""
    name_lower = name.lower().encode("latin-1")
    for key, value in headers:
        if key == name_lower:
            return value.decode("latin-1")
    return ""


def _build_url(scope: Dict[str, Any]) -> str:
    """Reconstruct the full URL from the ASGI scope."""
    scheme = scope.get("scheme", "https")
    headers = scope.get("headers", [])
    host = _get_header(headers, "host") or "localhost"
    root_path = scope.get("root_path", "")
    path = scope.get("path", "/")
    query_string = scope.get("query_string", b"")

    url = f"{scheme}://{host}{root_path}{path}"
    if query_string:
        url += f"?{query_string.decode('latin-1')}"
    return url


async def _send_response(
    send: Callable,
    status: int,
    body: bytes,
    content_type: str = "text/plain",
    extra_headers: List[Tuple[bytes, bytes]] = None,
) -> None:
    headers: List[Tuple[bytes, bytes]] = [
        (b"content-type", content_type.encode("latin-1")),
    ]
    if extra_headers:
        headers.extend(extra_headers)

    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": headers,
        }
    )
    await send(
        {
            "type": "http.response.body",
            "body": body,
        }
    )


async def _handle_return_request_url(scope: Dict[str, Any], send: Callable) -> None:
    url = _build_url(scope)
    await _send_response(send, 200, url.encode("utf-8"))


async def _handle_json(scope: Dict[str, Any], send: Callable) -> None:
    data = json.dumps({"message": "hello"}).encode("utf-8")
    await _send_response(send, 200, data, content_type="application/json")


async def _handle_set_cookies(scope: Dict[str, Any], send: Callable) -> None:
    await _send_response(
        send,
        200,
        b"cookies set",
        extra_headers=[
            (b"set-cookie", b"session=abc123; Path=/"),
            (b"set-cookie", b"theme=dark; Path=/"),
        ],
    )


async def _handle_binary(scope: Dict[str, Any], send: Callable) -> None:
    await _send_response(send, 200, b"\x00\x01\x02\x03\x04", content_type="application/octet-stream")


async def _handle_gzip(scope: Dict[str, Any], send: Callable) -> None:
    data = gzip.compress(json.dumps({"compressed": True}).encode("utf-8"))
    await _send_response(
        send,
        200,
        data,
        content_type="application/json",
        extra_headers=[(b"content-encoding", b"gzip")],
    )


async def _handle_echo_body(scope: Dict[str, Any], send: Callable, body: bytes) -> None:
    await _send_response(send, 200, body, content_type="text/plain")


async def _handle_not_found(scope: Dict[str, Any], send: Callable) -> None:
    await _send_response(send, 404, b"Not Found")
