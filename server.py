"""Local ReleaseGuard HTTP API and frontend."""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from engine import LIMIT, assess

ROOT = Path(__file__).resolve().parent
INPUT_FIELDS = ("patch", "coverage", "incidents", "network_flows", "npm_audit", "baseline_lock", "release_lock")
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/demo.json": ("demo.json", "application/json"),
    "/demo-moderate.json": ("demo-moderate.json", "application/json"),
    "/demo-payments.json": ("demo-payments.json", "application/json"),
    "/demo-go.json": ("demo-go.json", "application/json"),
}


class App(BaseHTTPRequestHandler):
    def send_headers(self, status, content_type, length=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if length is not None:
            self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        self.end_headers()

    def send_data(self, status, data, type_="application/json"):
        if isinstance(data, dict):
            data = json.dumps(data).encode()
        self.send_headers(status, type_, len(data))
        self.wfile.write(data)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/api/health":
            self.send_data(200, {"status": "ok"})
        elif path in STATIC:
            filename, type_ = STATIC[path]
            self.send_data(200, (ROOT / "web" / filename).read_bytes(), type_)
        else:
            self.send_data(404, {"error": "Page not found."})

    def do_POST(self):
        path = urlsplit(self.path).path
        if path not in {"/api/assess", "/api/assess/stream"}:
            self.send_data(404, {"error": "Endpoint not found."})
            return
        if self.headers.get_content_type() != "application/json":
            self.send_data(415, {"error": "Send application/json."})
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            size = 0
        if not 1 <= size <= len(INPUT_FIELDS) * 6 * LIMIT + 1024:
            self.send_data(413, {"error": "Request is empty or exceeds the size limit."})
            return
        try:
            data = json.loads(self.rfile.read(size))
            if not isinstance(data, dict):
                raise TypeError
            values = [data.get(field, "") for field in INPUT_FIELDS]
            if not all(isinstance(value, str) for value in values):
                raise TypeError
            if any(len(value.encode()) > LIMIT for value in values):
                self.send_data(413, {"error": "Each artifact must be 750 KB or smaller."})
                return
        except (json.JSONDecodeError, UnicodeError, TypeError, RecursionError):
            self.send_data(400, {"error": "Send a JSON object with text values for the evidence fields."})
            return
        if path == "/api/assess/stream":
            self.stream_assessment(values)
            return
        try:
            report = assess(*values)
        except (TypeError, RecursionError, UnicodeError):
            self.send_data(400, {"error": "Send a JSON object with text values for the evidence fields."})
            return
        except ValueError as error:
            self.send_data(422, {"error": str(error)})
            return
        self.send_data(200, report)

    def stream_assessment(self, values):
        self.close_connection = True
        self.send_headers(200, "application/x-ndjson; charset=utf-8")

        def send_event(event):
            self.wfile.write((json.dumps(event) + "\n").encode())
            self.wfile.flush()

        try:
            try:
                report = assess(*values, progress=send_event)
            except (UnicodeError, TypeError, RecursionError):
                send_event({"type": "error", "message": "The supplied evidence could not be processed."})
            except ValueError as error:
                send_event({"type": "error", "message": str(error)})
            else:
                send_event({"type": "result", "report": report})
        except (BrokenPipeError, ConnectionResetError):
            return

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    host = os.environ.get("RELEASEGUARD_HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8765"))
    try:
        with ThreadingHTTPServer((host, port), App) as server:
            print(f"ReleaseGuard is running at http://{host}:{port}", flush=True)
            server.serve_forever()
    except KeyboardInterrupt:
        print("\nReleaseGuard server stopped.")
