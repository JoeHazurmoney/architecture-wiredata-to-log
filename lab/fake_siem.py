#!/usr/bin/env python3
"""Stand-in SIEM HTTP event collector for the lab (--fault siem-down): answers 200 to every
post to /services/collector/event and appends the bodies to --out."""

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--port", type=int, default=8088)
    p.add_argument("--out", help="append received bodies here")
    a = p.parse_args()

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            if a.out:
                with open(a.out, "ab") as f:
                    f.write(body)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"text":"Success","code":0}')

        def log_message(self, *args):
            pass

    HTTPServer(("127.0.0.1", a.port), H).serve_forever()


if __name__ == "__main__":
    main()
