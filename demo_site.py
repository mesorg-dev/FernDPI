#!/usr/bin/env python3
"""Local 'blocked site' for manual ferndpi demo. TLS on 127.0.0.1:8443."""
import http.server
import ssl

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"hello from ferndpi demo site\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("demo-site:", fmt % args, flush=True)

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("demo/cert.pem", "demo/key.pem")
httpd = http.server.HTTPServer(("127.0.0.1", 8443), H)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
print("demo TLS site on https://127.0.0.1:8443", flush=True)
httpd.serve_forever()
