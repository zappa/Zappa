from typing import Any


def handler_for_events(event: Any, context: Any) -> bool:
    print("Event:", event)
    return True
