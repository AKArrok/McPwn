"""Intranet victim service for the fetch SSRF target.

A tiny HTTP server on 127.0.0.1 that only the *server side* of the MCP fetch
tool can reach (fetch runs on the same host). It answers with an internal
banner + a secret so McPwn's ``ssrf_internal_service`` signal has real
evidence: the response body carries ``Welcome to nginx!`` (banner shape) and a
secret value.

The service listens on several common dev ports by default (8000/8080/9211)
because an SSRF attacker (the McPwn agent) enumerates typical ports and must
be able to hit one of them; 127.0.0.1:80 is deliberately NOT used (system
reserved on this host).

Routes:
    /            -> banner + secret listing
    /secret      -> just the secret
    /healthz     -> internal health endpoint (banner only)

Run:  python eval/fetch_ssrf/intranet_server.py [--ports 8000,8080,9211]
"""

from __future__ import annotations

import argparse
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

SECRET = "TOP-SECRET-INTRANET-2026"
BANNER = "Welcome to nginx!"


class Handler(BaseHTTPRequestHandler):
    def _send(self, body: bytes, code: int = 200) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = self.path
        if path == "/secret":
            self._send(SECRET.encode())
        elif path == "/healthz":
            self._send(f"{BANNER} OK".encode())
        else:
            self._send(f"{BANNER}\ninternal secrets: {SECRET}\n".encode())

    def log_message(self, *args: object) -> None:  # silence request logs
        pass


def serve_one(host: str, port: int) -> None:
    HTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--ports", default="8000,8080,9211",
                        help="comma-separated ports to listen on")
    args = parser.parse_args()
    ports = [int(p) for p in args.ports.split(",") if p.strip()]
    threads = []
    for port in ports:
        t = threading.Thread(target=serve_one, args=(args.host, port), daemon=True)
        t.start()
        threads.append(t)
        print(f"[intranet] serving secrets on http://{args.host}:{port}", flush=True)
    for t in threads:
        t.join()
