import logging

from flask import Flask, request

app = Flask(__name__)


@app.route("/root-logger", methods=["GET", "POST"])
def return_request_url():
    logging.debug("debug message")
    logging.info("info message")
    logging.warning("warning message")
    logging.error("error message")
    logging.critical("critical message")
    return ""
