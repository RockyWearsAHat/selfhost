# Secure-VPN — a snapshot of the implementation, and where it really comes from

This directory holds a **copy** of the Secure-VPN program: the files installed on
this Mac at `~/.securevpn/app/`, vendored here on 2026-08-17 so the component
acting as this deployment's security boundary can be read, diffed and reverted
like every other part of the server.

## The upstream is the operator's own repository

```
https://github.com/RockyWearsAHat/Secure-VPN.git
```

That is not a third-party dependency and not inherited code. It is this operator's
own project, and **every file of the implementation is committed there, including
`server.py`** — 648 lines, the half that decides who gets in — alongside
`PROTOCOL.md`, `CRYPTOGRAPHY_EXPLAINED.md`, `test_security.py` and
`test_roster.py`.

**Corrected 2026-08-17.** An earlier revision of this file, and four documents
that followed it, said `server.py` had "never been committed" and existed only on
ALEX-DESKTOP. That was wrong. The mistake started in
`crates/app/cli/src/service_install.rs`, which named `scripts/securevpn/server.py`
— a path inside *this* repository that has never held anything — and its absence
was read as the code being absent from the world. The code was always in a
repository, just not this one. That is the `rui` situation `docs/principles.dx`
describes exactly: two repositories and no mechanism keeping copies equal, which
is a real problem worth writing down, and a completely different problem from
unreviewable code.

## What is in this directory

| File | Lines | What it is |
|---|---|---|
| `crypto_core.py` | 378 | Ed25519 identity, ephemeral X25519, HKDF, ChaCha20-Poly1305 with counter nonces, replay window, timestamp validation. Every primitive comes from the audited `cryptography` package; none of it is hand-rolled. |
| `protocol.py` | 432 | The three-packet handshake (`CLIENT_HELLO`, `SERVER_HELLO`, `CLIENT_AUTH`), the length-prefixed framing, `DATA`/`KEEPALIVE`/`REKEY`/`CLOSE`. **Behind upstream — see below.** |
| `client.py` | 351 | The client end. One authenticated session per local connection, so parallel browser connections do not interleave in one tunnel. This is the program `crates/ui/vpn-ui` spawns. |
| `key_manager.py` | 361 | Identity generation, on-disk key format (`securevpn-ed25519 <base64> <name>`), peer public keys. |
| `config.py` | 32 | `.env` loading. |

`server.py` is **not** copied here, and that is now a choice rather than a
symptom: this Mac is a client, the server runs on ALEX-DESKTOP, and the
authoritative source for both is the repository above. Read `server.py` there, or
in a clone.

## This is a copy, and this copy has already drifted

Checked against upstream `main` (`437108e`, 2026-08-15) on 2026-08-17:

| File | This copy vs upstream |
|---|---|
| `client.py` | identical (`ac8d1f8b…`) |
| `config.py` | identical (`503bde11…`) |
| `crypto_core.py` | identical (`44ed1dd3…`) |
| `key_manager.py` | identical (`f8ac6412…`) |
| `protocol.py` | **behind**: this copy is `47da66d4…` (432 lines), upstream is `c17a583f…` (496 lines) |

The difference is real and it matters: upstream's `protocol.py` carries the
multi-peer roster — `SecureVPNProtocol(peer_roster=…)`, `_resolve_peer`, and
`HandshakeState.peer_name`, the field the whole identity carry rests on. The copy
installed on this Mac predates it and knows only a single peer. So this laptop's
client is one commit behind the implementation the design documents describe,
which is exactly the kind of thing a stamped copy exists to reveal.

An earlier revision of this file asserted the opposite — that this copy carried
fixes upstream lacked, so replacing it with a clone would lose work. Four of the
five files are byte-identical to upstream and the fifth is *older*, so upstream
has the client-side fixes and there is nothing here to lose by updating.

These are the SHA-256 digests of `~/.securevpn/app/` as it stood when this
directory was created:

```
ac8d1f8bc4e9046860e6a96fef66581425cf0a84ea9a043089f2d31365fafa49  client.py
503bde11778b33eaf937d30e87212d33878fa81cb8e075ec7e58de644f8e8175  config.py
44ed1dd3205db3c37dfe4cbab371df409017bc6a51b5d159e1aff26bc26bb2c2  crypto_core.py
f8ac641283cfee2d4ca514bcb6dc5352116302b4134438327a93a62d281fc22f  key_manager.py
47da66d480bb33c6c2a87c7a69911a08a90798b15b4611d74bd9633ffa219bf1  protocol.py
```

To check that the installed copy has not drifted from this reviewed one:

```sh
shasum -a 256 ~/.securevpn/app/*.py | sed 's|.*/||' | sort
shasum -a 256 scripts/securevpn/app/*.py | sed 's|.*/||' | sort
```

A difference means somebody edited the installed copy in place. Reconcile it here
first — this side is the reviewed one — and then reinstall. To check either
against the source of truth, clone the repository above and diff.

## `--peer-forward`, and which `server.py` a box is running

`crates/services/vpn/src/runner.rs` launches a relay with
`--peer-forward <peer>=<socket>` for every roster entry that declares a
`forward_port`. That flag is implemented in `server.py` **upstream**; it is not in
any copy that predates it, and Python's `argparse` exits non-zero on an argument
it does not recognise. So the question a deployment has to answer is not "does
the implementation exist" but "**is the copy installed on this box new enough**".
`Relays::preflight` puts that requirement in the relay's own service log before the
first start rather than after it.

## `join-mac.sh` clones this repository, and no longer destroys anything

`scripts/securevpn/join-mac.sh` installs the client by cloning the repository
above into `~/.securevpn/app`. It used to `rm -rf` that directory first whenever it
had no `.git` — which is exactly the state a hand-copied install is in — so
running it on a working machine deleted the working install. It does not do that
any more: it adopts an existing directory as a checkout without overwriting a
single file, and reports what differs from upstream. See the script's own comments
and its output.

## Reinstalling from here

With this directory present, the same layout is one copy:

```sh
mkdir -p ~/.securevpn/app && cp scripts/securevpn/app/*.py ~/.securevpn/app/
```

Prefer a clone of the repository above when what you want is current code; prefer
this directory when what you want is *this reviewed snapshot*. The Windows box
takes the same flat layout under `C:\ProgramData\selfhost\securevpn\`, which is why
these files sit in one directory with no package structure: `protocol.py` imports
`crypto_core` by bare name, so the directory *is* the import path and splitting it
would break both installs.

## What this directory must never contain

Keys. `~/.securevpn/keys/` and `C:\ProgramData\selfhost\securevpn\keys` hold the
private key that is this relay's whole perimeter, and `docs/SECURITY.md` forbids a
secret in a committed file. `key_manager.py` is the code that handles them; the
material itself stays on the machines that need it, in a directory this repository
never writes.
