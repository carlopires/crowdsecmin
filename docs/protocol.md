# Wire protocol

Two different protocols are involved:

- **LAPI v1** — between the Go bouncer and `cslite` (Mode B server).
- **CAPI v3** — between `cslite` and `api.crowdsec.net` (client).

## LAPI v1 (server, Mode B)

Plain HTTP/1.1 on `127.0.0.1:8080`. Requests carry `X-Api-Key`; an invalid or
missing key returns:

```http
HTTP/1.1 403 Forbidden
Content-Type: application/json
Content-Length: 30

{"message":"access forbidden"}
```

### Endpoints

| method | path | notes |
|---|---|---|
| GET | `/v1/decisions/stream?startup=true` | full snapshot, chunked |
| GET | `/v1/decisions/stream?startup=false` | delta since the caller's cursor |
| GET | `/v1/decisions` | snapshot in the stream envelope |
| POST | `/v1/decisions` | add from a bare decision or `{"new":[…]}` |
| DELETE | `/v1/decisions?value=IP[/CIDR]` | remove |
| GET/POST | `/v1/bouncers` | list names / create a key |
| GET | `/health` | `{"status":"up"}`, unauthenticated |
| GET | `/v1/heartbeat` | `200`, `Content-Length: 0` |
| POST | `/v1/usage-metrics` | accepted and dropped (`200`) |

Large responses use `Transfer-Encoding: chunked` and `Content-Type:
application/json`. Unimplemented paths return `501` with a JSON body.

### Stream envelope

```json
{"new": [ <decision>, ... ], "deleted": [ <decision>, ... ]}
```

### Decision object

```json
{
  "duration": "40h14m3s",
  "id": 13830376,
  "origin": "CAPI",
  "scenario": "ssh:bruteforce",
  "scope": "Ip",
  "type": "ban",
  "value": "193.32.249.159"
}
```

- `duration`: **remaining** time, Go format `[Nh][Nm][Ns]` (e.g. `14m35s`).
- `scope`: `Ip` (address) or `Range` (CIDR); `type`: `ban`.
- `value`: IPv4/IPv6 literal or CIDR, never with a port.
- Field names/nesting matter; whitespace does not.

## CAPI v3 (client)

Use the **v3** prefix; v1 is the local LAPI and returns `403` here.

```http
POST /v3/watchers/login  Content-Type: application/json
{"machine_id":"<id>","password":"<pw>"}
→ 200 {"token":"<JWT>","expire":"<RFC3339>"}

GET /v3/decisions/stream?startup=true&scopes=Ip,Range
Authorization: Bearer <JWT>
```

The v3 body is **grouped**, not flat:

```json
{
  "new": [
    {"scope": "ip", "scenario": "ssh:bruteforce",
     "decisions": [{"value": "185.220.101.0", "duration": "164h"}]}
  ],
  "deleted": [
    {"scope": "ip", "decisions": ["50.116.60.177"]}
  ],
  "links": {}
}
```

Pitfalls:

- **v3 only**: `/v1/watchers/login` and `/v1/decisions/stream` against CAPI return
  `403`.
- **Do not send `community_pull=false`**: it disables the community blocklist
  and returns an empty payload (55 bytes). The parameter belongs to the local v1
  API.
- Deltas are polled every `update_frequency` (10 s, like the Go engine);
  `capi.update_frequency` (2 h) is a periodic **full refresh**.
- CAPI may close TLS without `close_notify`; treat that as EOF.

## Compatibility notes

- Tested with the unmodified `crowdsec-firewall-bouncer` v0.0.36.
- `GET /v1/decisions` returns the stream envelope, not `cscli`'s alert-shaped
  JSON; `cscli` parity is partial.
- Bouncer keys created via `POST /v1/bouncers` are in-memory (not persisted).
