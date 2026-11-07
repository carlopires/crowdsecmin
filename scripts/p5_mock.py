#!/usr/bin/env python3
"""Mock CAPI (v3, snapshot) for the P5/P7 direct-mode tests.

CAPI v3 returns the full blocklist on every request; this mock emulates that:
  call 1     -> fixture
  calls 2-3  -> fixture + 192.0.2.123
  call 4+    -> fixture            (entry disappears -> prune should remove it)
"""
import copy
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
base = {
    "new": [{"scope": s, "scenario": sc, "decisions": ds} for (s, sc), ds in groups.items()],
    "deleted": [],
    "links": {},
}
with_extra = copy.deepcopy(base)
with_extra["new"].append(
    {
        "scope": "ip",
        "scenario": "ssh:bf",
        "decisions": [{"value": "192.0.2.123", "duration": "1h"}],
    }
)
state = {"calls": 0}


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
            state["calls"] += 1
            if state["calls"] == 1:
                body = base
            elif state["calls"] <= 3:
                body = with_extra
            else:
                body = base
            self._send(200, json.dumps(body, separators=(",", ":")).encode())
        else:
            self._send(404, b'{"message":"not found"}')


http.server.HTTPServer(("127.0.0.1", port), Handler).serve_forever()
