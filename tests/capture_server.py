"""Local HTTP capture server for sshsentry tests (webhook, Slack and sharing endpoints).

Records every POST as {"path", "headers", "body", "json"}. Special paths:
  /fail -> HTTP 500    /slow -> waits 3 s, then 200    anything else -> 200
Use in-process (CaptureServer().start()) or standalone: python3 capture_server.py PORT [OUT.jsonl]
"""
import json, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class CaptureServer:
    def __init__(self, port=0, out=None):
        self.requests, self.out, cap = [], out, self
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode("utf-8", "replace")
                try:
                    parsed = json.loads(body)
                except ValueError:
                    parsed = None
                rec = {"path": self.path, "headers": dict(self.headers), "body": body, "json": parsed}
                cap.requests.append(rec)
                if cap.out:
                    with open(cap.out, "a") as f:
                        f.write(json.dumps(rec) + "\n")
                if self.path.startswith("/slow"):
                    time.sleep(3)
                code = 500 if self.path.startswith("/fail") else 200
                try:
                    self.send_response(code); self.end_headers(); self.wfile.write(b"ok")
                except (BrokenPipeError, ConnectionResetError):
                    pass   # client gave up (timeout test)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), H)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.url = f"http://localhost:{self.port}"

    def start(self):
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self.httpd.shutdown(); self.httpd.server_close()

    def clear(self):
        self.requests.clear()

    def at(self, path):
        return [r for r in self.requests if r["path"] == path]


if __name__ == "__main__":
    s = CaptureServer(int(sys.argv[1]) if len(sys.argv) > 1 else 8765, sys.argv[2] if len(sys.argv) > 2 else None)
    print(f"capturing on {s.url}", flush=True)
    s.httpd.serve_forever()
