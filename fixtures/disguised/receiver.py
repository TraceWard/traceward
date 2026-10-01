"""Loopback-only sink for the synthetic demo; never prints the request body."""

from http.server import BaseHTTPRequestHandler, HTTPServer


class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        count = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(count)
        print(f"received {count} synthetic bytes from loopback", flush=True)
        self.send_response(204)
        self.end_headers()


HTTPServer(("127.0.0.1", 8800), Receiver).serve_forever()
