#!/usr/bin/env python3
"""Mock CAPI (v3, grouped) for the P5/P7 direct-mode tests.

startup=true  -> fixture converted to v3 groups
deltas 1..3   -> grouped add 192.0.2.123
delta 4       -> grouped delete 192.0.2.123
delta 5+      -> empty
"""
import http.server
import json
import sys

port = int(sys.argv[1])
flat = json.load(open(sys.argv[2]))

groups = {}
for d in flat.get("new", []):
    scope = d.get("scope", "Ip").lower()
    key = (scope, d.get("scenario", ""))
    groups.setdefault(key, []).append({"value": d["value"], "duration": d["duration"]})
v3 = {
    "new": [
        {"scope": s, "scenario": sc, "decisions": ds}
        for (s, sc), ds in groups.items()
    ],
    "deleted": [],
    "links": {},
}
fixture = json.dumps(v3, separators=(",", ":")).encode()
state = {"delta": 0}


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(n)
        if self.path in ("/v3/watchers/login", "/v1/watchers/login"):
            self._send(200, b'{"token":"testtoken","expire":"2030-01-01T00:00:00Z"}')
        else:
            self._send(404, b'{"message":"not found"}')

    def do_GET(self):
        if not self.headers.get("Authorization", "").startswith("Bearer testtoken"):
            self._send(401, b'{"message":"unauthorized"}')
            return
        if "/decisions/stream" in self.path:
            if "startup=true" in self.path:
                self._send(200, fixture)
            else:
                state["delta"] += 1
                d = state["delta"]
                if d <= 3:
                    body = (
                        b'{"new":[{"scope":"ip","scenario":"ssh:bf",'
                        b'"decisions":[{"value":"192.0.2.123","duration":"1h"}]}],'
                        b'"deleted":[]}'
                    )
                elif d == 4:
                    body = b'{"new":[],"deleted":[{"scope":"ip","decisions":["192.0.2.123"]}]}'
                else:
                    body = b'{"new":[],"deleted":[]}'
                self._send(200, body)
        else:
            self._send(404, b'{"message":"not found"}')


http.server.HTTPServer(("127.0.0.1", port), Handler).serve_forever()
