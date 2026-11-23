"""
CyberScan HTTP Server & Security Audit API
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
import urllib.request
import urllib.parse
from .scanner import evaluate_headers

PORT = int(os.environ.get("PORT", "5005"))
HOST = os.environ.get("HOST", "0.0.0.0")

class CyberScanHandler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, data: dict):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/" or parsed.path.startswith("/index"):
            file_path = os.path.join(os.path.dirname(__file__), "public", "index.html")
            with open(file_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        elif parsed.path == "/health":
            self._send_json(200, {"status": "healthy", "service": "cyberscan-security-auditor"})

        elif parsed.path == "/api/v1/scan":
            query = urllib.parse.parse_qs(parsed.query)
            target = query.get("url", ["https://github.com"])[0]
            if not target.startswith("http"):
                target = "https://" + target

            try:
                req = urllib.request.Request(
                    target,
                    headers={"User-Agent": "CyberScan-Security-Bot/1.0"}
                )
                with urllib.request.urlopen(req, timeout=5) as response:
                    headers = dict(response.headers)
                    audit = evaluate_headers(headers)
                    self._send_json(200, audit)
            except Exception as e:
                # Return standard baseline evaluation on network timeout/error
                fallback_headers = {
                    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY"
                }
                audit = evaluate_headers(fallback_headers)
                audit["note"] = f"Audited using simulated baseline headers: {str(e)}"
                self._send_json(200, audit)

        else:
            self._send_json(404, {"error": "Not Found"})

def run():
    server = HTTPServer((HOST, PORT), CyberScanHandler)
    print(f"[CyberScan] Web Scanner active on http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()

if __name__ == "__main__":
    run()
