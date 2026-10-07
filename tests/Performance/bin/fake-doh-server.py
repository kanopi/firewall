#!/usr/bin/env python3
"""A DNS-over-HTTPS server whose behaviour can be chosen, for benchmarking (#480).

`DnsOverHttpResolver` bounds every lookup with curl's timeouts, and the claim that matters
is that the slowest request is capped by `timeout_ms` rather than by whoever answers. A
public provider can't be told to be slow, or to answer just over the limit, so this stands
in for one: it answers the JSON API Cloudflare and Google share (`dns-json`) over TLS,
after a delay, or not at all.

Threaded, because the probe sends 25 workers at once and a server that served them one at a
time would measure its own queue rather than the resolver.

Usage:
  fake-doh-server.py --cert C --key K --port P [--delay-ms N] [--mode MODE]

Modes:
  normal    PTR for 66.249.66.1 is a Googlebot name; its A record comes back to it
  many-ptr  the PTR answer lists 15 invented crawl-N.googlebot.com names (#475's cap)
  hang      accept the connection and never answer
  servfail  answer every query with Status 2
"""

import argparse
import json
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

GOOGLEBOT_PTR = "1.66.249.66.in-addr.arpa"
GOOGLEBOT_HOST = "crawl-66-249-66-1.googlebot.com"
GOOGLEBOT_IP = "66.249.66.1"
TYPE_CODES = {"A": 1, "PTR": 12, "AAAA": 28}


def answer(mode, name, qtype):
    """The JSON body for one query."""
    if mode == "servfail":
        return {"Status": 2}

    name = name.rstrip(".").lower()
    records = []

    if qtype == "PTR" and name == GOOGLEBOT_PTR:
        hosts = [f"crawl-{i}.googlebot.com." for i in range(15)] if mode == "many-ptr" else [GOOGLEBOT_HOST + "."]
        records = [{"name": name, "type": 12, "TTL": 300, "data": host} for host in hosts]
    elif qtype == "A" and name == GOOGLEBOT_HOST:
        records = [{"name": name, "type": 1, "TTL": 300, "data": GOOGLEBOT_IP}]

    if not records:
        return {"Status": 3, "Question": [{"name": name, "type": TYPE_CODES.get(qtype, 0)}]}

    return {"Status": 0, "Question": [{"name": name, "type": TYPE_CODES.get(qtype, 0)}], "Answer": records}


def handler_for(mode, delay):
    """A request handler bound to one mode and delay."""

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            if mode == "hang":
                # Hold the connection open and say nothing; curl's timeout must end it.
                time.sleep(3600)
                return

            if delay > 0:
                time.sleep(delay)

            query = parse_qs(urlparse(self.path).query)
            body = json.dumps(answer(mode, query.get("name", [""])[0], query.get("type", [""])[0])).encode()

            self.send_response(200)
            self.send_header("Content-Type", "application/dns-json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            # Quiet: the probe reports what matters, and 75 lines of access log would bury it.
            pass

    return Handler


class QuietServer(ThreadingHTTPServer):
    """Ignores clients that hang up.

    Each probe worker keeps its connection open for reuse and drops it when the process
    exits, and the standard server prints a traceback for every one.
    """

    def handle_error(self, request, client_address):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--delay-ms", type=float, default=0.0)
    parser.add_argument("--mode", choices=["normal", "many-ptr", "hang", "servfail"], default="normal")
    args = parser.parse_args()

    server = QuietServer(("127.0.0.1", args.port), handler_for(args.mode, args.delay_ms / 1000))
    server.daemon_threads = True

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"fake DoH server on 127.0.0.1:{args.port} mode={args.mode} delay={args.delay_ms:.0f}ms", flush=True)

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
