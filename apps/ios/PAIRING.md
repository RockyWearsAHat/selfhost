# Pairing the iPhone app with a Self-Host server

This document is the contract between the iOS app (`apps/ios/SelfHostPhone`) and
the server side. It defines the QR/pairing payload the app parses today, lists
the existing admin-API endpoints the app is built against, and specifies the
server work needed to make pairing first-class. The Swift parser lives in
`SelfHostPhone/Pairing/PairingPayload.swift`; anything generating QR codes must
match this page exactly.

## 1. The pairing payload

One payload, two encodings. A QR code should carry the **URL form** (compact,
scans reliably); anything printed for a human to copy should offer the **JSON
form** too. The app accepts either, scanned or pasted.

### URL form

```
selfhost-pair://v1/?host=192.168.1.20&port=9191&token=<64-hex>&kind=admin&name=home-server&tls=0
```

### JSON form

```json
{
  "type": "selfhost-pair",
  "v": 1,
  "host": "192.168.1.20",
  "port": 9191,
  "token": "0123…ef",
  "tokenKind": "admin",
  "name": "home-server",
  "tls": false,
  "fingerprint": null
}
```

### Fields

| field (JSON / URL) | required | meaning |
|---|---|---|
| `type` / — | JSON only | Literal `"selfhost-pair"`, so a random JSON blob is refused. The URL form's scheme plays this role. |
| `v` / host part `v1` | yes | Payload version. The app refuses anything but `1`. |
| `host` / `host` | yes | Address the admin API is reachable at **from the phone**: a LAN IP, a Tailscale/WireGuard address, or a gateway hostname. Not `127.0.0.1`. |
| `port` / `port` | yes | TCP port of the admin API. The daemon's default is `9191` (`admin_bind` in `selfhost.config.toml`). |
| `token` / `token` | yes | The secret. Interpreted per `tokenKind`. |
| `tokenKind` / `kind` | no, default `admin` | `"admin"`: the daemon's `data/admin.token` verbatim — a long-lived credential the app stores directly. `"pairing"`: a single-use token the app exchanges via `POST /api/pair` (section 4.1). |
| `name` / `name` | no | Human name for the server, shown as the dashboard title. Falls back to `host`. |
| `tls` / `tls` (`1`/`true`) | no, default false | Whether the app speaks HTTPS to `host:port`. |
| `fingerprint` / `fp` | no | SHA-256 of the server's **DER-encoded leaf certificate**, 64 hex chars (colons tolerated). Only valid with `tls`. When present, the app pins: connections are refused unless the presented certificate hashes to exactly this value, and the system trust store is not consulted — trust is anchored in the scan, like an SSH host key. |

The app stores the resulting credential (host, port, tls, fingerprint, token) as
a single Keychain item (`kSecClassGenericPassword`, accessible after first
unlock, this-device-only). Pairing again replaces it; "Unpair" deletes it.

### Generating a payload today (no server changes)

The `admin` kind works against the current daemon:

```sh
# On the server, e.g. print a QR in the terminal:
qrencode -t ANSIUTF8 "selfhost-pair://v1/?host=$(tailscale ip -4)&port=9191&token=$(cat data/admin.token)&kind=admin&name=$(hostname)"
```

## 2. Reachability — the part pairing cannot paper over

The admin API **binds loopback only and refuses anything else**
(`selfhost_admin::bind`), by design: the port is protected by a bearer token
alone, and the sanctioned remote transport is an SSH tunnel. An iPhone cannot
maintain an OpenSSH `-L` tunnel, so the operator must give the phone a path to
the port. Sanctioned options, in order of preference:

1. **Overlay VPN (Tailscale/WireGuard) with a loopback forward.** The daemon
   stays loopback-only; a forwarder on the server (e.g. `tailscale serve
   --tcp 9191 tcp://127.0.0.1:9191`, or any authenticated tunnel terminating on
   the server) exposes the port only inside the operator's private network.
   Payload: `host` = overlay address, `tls` = false. The VPN provides transport
   encryption and authentication; the bearer token still gates every request.
2. **The mobile gateway listener (section 4.2)** — new server work: TLS with a
   pinned certificate, safe to expose beyond loopback because every request is
   token-gated *and* the transport is encrypted end-to-end.

Plain HTTP across an untrusted network is not an option the payload should ever
describe: the bearer token would travel in cleartext. This is why the app's ATS
exception exists but the doc insists on VPN or TLS.

## 3. Existing endpoints the app uses (already implemented, `crates/admin`)

All under `http(s)://<host>:<port>`, all JSON, auth =
`Authorization: Bearer <token>` unless noted. Errors are
`{"error": "<message>"}` with 400/401/404/413/500; validation failures are
`422 {"problems": [{"field": "…", "message": "…"}]}`. `401` never distinguishes
missing from wrong tokens.

| method & path | auth | response (200/202) |
|---|---|---|
| `GET /api/health` | none | `{"ok": true}` — reachability probe, deliberately says nothing else. |
| `GET /api/services` | yes | `{"services": [ServiceStatus…]}` |
| `GET /api/services/{name}` | yes | `{"status": ServiceStatus, "spec": ServiceSpec}` |
| `POST /api/services/{name}/start` (also `stop`, `restart`) | yes | `202 {"accepted": "<action>", "service": "<name>"}` — accepted, not finished; poll for the outcome. |
| `GET /api/services/{name}/logs?from=N&limit=M` | yes | `{"lines": [{"seq": u64, "stream": "stdout"\|"stderr", "text": "…"}], "nextSeq": u64, "missed": u64}` — everything after `N`, `limit` capped at 5000, default 500. |

`ServiceStatus` (flat object): `name`, `displayName`, `description`,
`startMode` (`automatic|manual|disabled`), `totalRestarts`, `logSeq`, `state`
(`stopped|disabled|starting|running|stopping|exited|backoff|gave-up|unstartable`)
plus state-specific fields: `pid`+`uptimeSecs` (running), `code` (exited,
null = signal), `retryInSecs`+`attempt` (backoff), `attempts`+`reason`
(gave-up), `reason` (unstartable).

`ServiceSpec`: `name`, `displayName`, `description`, `program`, `args`, `env`,
`cwd`, `node`, `startMode`, `restart` (`never|on-failure|always`),
`restartDelaySecs`, `maxRestarts`, `stopTimeoutSecs`, `stopCommand`, `git`
(nullable: `repository`, `branch`, `path`, `intervalSecs`, `enabled`,
`autoUpdate`, `postPull`).

The app also parses `PUT /api/services/{name}` error shapes but does not install
services; definition editing stays with the desktop console.

## 4. Server work required (specified here, **not yet implemented**)

The app is already coded against 4.1; it works the moment the endpoint lands.
Until then, `tokenKind: "admin"` payloads are fully functional.

### 4.1 `POST /api/pair` — exchange a single-use pairing token

Why: putting `data/admin.token` itself in a QR code makes the QR a permanent
credential — anyone who photographs the operator's screen owns the server until
the token file is rotated, and rotation logs out every console. A pairing token
is worthless sixty seconds later, and each device gets its own revocable
credential.

- **Auth:** none (the pairing token in the body is the credential).
- **Request:**

  ```json
  {
    "pairingToken": "<hex, from the QR>",
    "device": { "name": "Alex's iPhone", "platform": "ios" }
  }
  ```

- **Response `200`:**

  ```json
  { "token": "<64-hex long-lived device token>", "serverName": "home-server" }
  ```

  `serverName` is optional; the app falls back to the payload's `name`.

- **Errors:** `401 {"error": "authorisation required"}` for an unknown, spent,
  or expired pairing token — the same body as every other 401, telling a
  guesser nothing. `400` for malformed JSON.

- **Semantics:** pairing tokens are minted by a new CLI verb (suggested:
  `selfhost pair`, which prints the QR payload from section 1 with
  `kind=pairing`), are single-use, expire after ~5 minutes, and are compared in
  constant time like `Token::matches`. Device tokens must be accepted by the
  existing bearer check alongside the admin token (a list of valid tokens
  rather than one), persisted with the device name so
  `selfhost devices`/`revoke` can list and revoke them individually.

### 4.2 A reachable, TLS-terminated listener (the "mobile gateway")

Why: section 2 — loopback-only is correct for the trust model, but the phone
needs *some* sanctioned path. If the VPN route is judged too much operator
burden, add an opt-in second listener:

- Config: `mobile_bind = "0.0.0.0:9192"` (absent = feature off, nothing
  changes today).
- Serves the same `Api::handle` routes over TLS with a self-signed certificate
  generated once into `data/`; the certificate's SHA-256 goes into the pairing
  payload as `fingerprint`, and `tls` is set — the phone pins it, so no CA is
  involved and MITM fails closed.
- Refuses to serve `/api/pair`-minted tokens over plain HTTP; refuses to start
  if configured without TLS.

### 4.3 QR generation (`selfhost pair`)

A CLI verb that mints a pairing token (4.1), assembles the section-1 payload
(URL form) with the server's best guess of its reachable address (flag
`--host` to override), and renders it as a QR in the terminal plus the JSON
form for copy-paste. Until 4.1 exists, `selfhost pair --admin-token` can emit
the `kind=admin` payload as a stopgap.

## 5. Threat-model notes for the implementer

- The QR payload is a secret while it carries `kind=admin`; prefer 4.1 so it
  carries only a short-lived token.
- The app proves a credential (one authenticated `GET /api/services`) **before**
  storing it, so a stale QR fails at pairing time, visibly.
- The app never falls back from pinned-TLS to plain HTTP; a pin mismatch is a
  hard connection failure.
- Device tokens inherit the admin token's power. Revocation (4.1) is the
  mechanism that keeps a lost phone from being a lost server.
