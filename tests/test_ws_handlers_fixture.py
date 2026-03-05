"""WebSocket handlers module for testing auto-import in LambdaHandler."""

from zappa.websocket import on_connect, on_disconnect, on_message


@on_connect
def handle_connect(event, context):
    return {"statusCode": 200, "body": "connected"}


@on_disconnect
def handle_disconnect(event, context):
    return {"statusCode": 200, "body": "disconnected"}


@on_message
def handle_message(event, context):
    return {"statusCode": 200, "body": event.get("body", "")}
