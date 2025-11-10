from flask import Flask, request

app = Flask(__name__)


@app.route("/return/request/url", methods=["GET", "POST"])
def return_request_url():
    return request.url


@app.route("/debug/wsgi/environ", methods=["GET"])  # Route without stage prefix (Flask sees clean path)
def debug_wsgi_environ():
    """Debug endpoint to inspect WSGI environ values"""
    script_name = request.environ.get("SCRIPT_NAME", "")
    path_info = request.environ.get("PATH_INFO", "")
    return f"SCRIPT_NAME={script_name!r} PATH_INFO={path_info!r} URL={request.url}"
