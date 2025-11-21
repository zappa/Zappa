import logging

import pytest

from zappa.handler import LambdaHandler

"""
https://github.com/zappa/Zappa/issues/1336
2024-08-13 @ceturc
Test that the root logger's level is updated when log_level is set.
This was Zappa's default behavior prior to 0.59.0.  This test is
designed to prevent future regressions of logging.
"""

event = {
    "body": "",
    "resource": "/{proxy+}",
    "requestContext": {},
    "queryStringParameters": {},
    "headers": {
        "Host": "example.com",
    },
    "pathParameters": {"proxy": "root-logger"},
    "httpMethod": "GET",
    "stageVariables": {},
    "path": "/root-logger",
}


@pytest.fixture()
def reset_handler_singleton():
    """
    Since the LambdaHandler is a singleton, it must be
    destroyed before tests for logging changes to take effect.
    """
    LambdaHandler._LambdaHandler__instance = None
    yield


def test_wsgi_root_log_level_debug(caplog, reset_handler_singleton):
    lh = LambdaHandler("tests.test_wsgi_root_log_level_settings_debug")
    response = lh.handler(event, None)
    assert response["statusCode"] == 200
    assert ("root", logging.DEBUG, "debug message") in caplog.record_tuples
    assert ("root", logging.INFO, "info message") in caplog.record_tuples
    assert ("root", logging.WARNING, "warning message") in caplog.record_tuples
    assert ("root", logging.ERROR, "error message") in caplog.record_tuples
    assert ("root", logging.CRITICAL, "critical message") in caplog.record_tuples


def test_wsgi_root_log_level_info(caplog, reset_handler_singleton):
    lh = LambdaHandler("tests.test_wsgi_root_log_level_settings_info")
    response = lh.handler(event, None)
    assert response["statusCode"] == 200
    assert ("root", logging.DEBUG, "debug message") not in caplog.record_tuples
    assert ("root", logging.INFO, "info message") in caplog.record_tuples
    assert ("root", logging.WARNING, "warning message") in caplog.record_tuples
    assert ("root", logging.ERROR, "error message") in caplog.record_tuples
    assert ("root", logging.CRITICAL, "critical message") in caplog.record_tuples
