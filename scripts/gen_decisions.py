#!/usr/bin/env python3
"""Generate a CrowdSec /v1/decisions/stream payload (~2.1 MB, 15344 decisions).

Deterministic (fixed seed). Values are canonical and globally unique so that
`ipset hash:net` normalisation cannot collapse them (T1 checks exact counts).
"""
import ipaddress
import json
import random
import sys

N = 15344
rng = random.Random(20261107)
SCEN = ["ssh:bruteforce", "ssh:bruteforce", "crowdsecurity/ssh-bf",
        "ssh:slow-bf", "ssh:refused-conn", "http:flood"]


def gdur(sec):
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    out = ""
    if h:
        out += f"{h}h"
    if m:
        out += f"{m}m"
    if s or not out:
        out += f"{s}s"
    return out


def ip4():
    return ".".join(str(rng.randint(1, 254)) for _ in range(4))


def ip6():
    return "2001:db8::" + ":".join("%x" % rng.randint(0, 0xffff) for _ in range(4))


seen = set()


def unique_value():
    """Return (value, scope) that is canonical and globally unique."""
    while True:
        r = rng.random()
        try:
            if r < 0.89:
                v, scope = ip4(), "Ip"
            elif r < 0.97:
                plen = rng.choice([20, 24, 26, 28, 30])
                v = str(ipaddress.ip_network(f"{ip4()}/{plen}", strict=False))
                scope = "Range"
            else:
                if rng.random() < 0.5:
                    v, scope = ip6(), "Ip"
                else:
                    plen = rng.choice([48, 56, 64, 120])
                    v = str(ipaddress.ip_network(f"{ip6()}/{plen}", strict=False))
                    scope = "Range"
        except ValueError:
            continue
        if v not in seen:
            seen.add(v)
            return v, scope


dec = []
for i in range(N):
    value, scope = unique_value()
    dec.append({
        "duration": gdur(rng.randint(3600, 172800)),
        "id": 13000000 + i,
        "origin": "CAPI" if rng.random() < 0.85 else "crowdsec",
        "scenario": rng.choice(SCEN),
        "scope": scope,
        "type": "ban",
        "value": value,
    })

payload = {"new": dec, "deleted": []}
out = sys.argv[1] if len(sys.argv) > 1 else "decisions.json"
with open(out, "w") as f:
    json.dump(payload, f, separators=(",", ":"))
import os
print(f"{out}: {os.path.getsize(out)} bytes, {len(dec)} decisions, {len(seen)} unique")
