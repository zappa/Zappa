###
# This test application exists to confirm how Zappa handles WSGI application
# _responses_ when Binary Support is enabled.
###

import io
import json

from flask import Flask, Response, send_file

app = Flask(__name__)


@app.route("/textplain_mimetype_response1", methods=["GET"])
def text_mimetype_response_1():
    return Response(response="OK", mimetype="text/plain")


@app.route("/textarbitrary_mimetype_response1", methods=["GET"])
def text_mimetype_response_2():
    return Response(response="OK", mimetype="text/arbitary")


@app.route("/json_mimetype_response1", methods=["GET"])
def json_mimetype_response_1():
    return Response(response=json.dumps({"some": "data"}), mimetype="application/json")


@app.route("/arbitrarybinary_mimetype_response1", methods=["GET"])
def arbitrary_mimetype_response_1():
    return Response(response=b"some binary data", mimetype="arbitrary/binary_mimetype")
