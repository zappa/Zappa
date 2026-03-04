"""Minimal WSGI app for WebSocket handler tests."""


def app(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"OK"]
