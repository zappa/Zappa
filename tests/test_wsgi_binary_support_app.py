"""
This test application exists to confirm how Zappa handles WSGI application
_responses_ when Binary Support is enabled.
"""

import gzip
import json

from flask import Flask, Response

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


@app.route("/arbitrarybinary_mimetype_response2", methods=["GET"])
def arbitrary_mimetype_response_3():
    return Response(response="doesnt_matter", mimetype="definitely_not_text")


@app.route("/content_encoding_header_json1", methods=["GET"])
def response_with_content_encoding_1():
    return Response(
        response=gzip.compress(json.dumps({"some": "data"}).encode()),
        mimetype="application/json",
        headers={"Content-Encoding": "gzip"},
    )


@app.route("/content_encoding_header_textarbitrary1", methods=["GET"])
def response_with_content_encoding_2():
    return Response(
        response=b"OK",
        mimetype="text/arbitrary",
        headers={"Content-Encoding": "something_arbitrarily_binary"},
    )


@app.route("/content_encoding_header_textarbitrary2", methods=["GET"])
def response_with_content_encoding_3():
    return Response(
        response="OK",
        mimetype="text/arbitrary",
        headers={"Content-Encoding": "with_content_type_but_not_bytes_response"},
    )


@app.route("/userdefined_additional_mimetype_response1", methods=["GET"])
def response_with_userdefined_addtional_mimetype():
    return Response(
        response="OK",
        mimetype="application/vnd.oai.openapi",
    )
