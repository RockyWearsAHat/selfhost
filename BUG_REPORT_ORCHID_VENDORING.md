# Bug Report: Orchid Image Server Should Vendor HTTP Implementation

## Issue
The orchid-images service currently uses the `hyper` HTTP framework and multiple external dependencies when it should implement HTTP entirely in-house, following selfhost's design philosophy.

## Current State
- Uses `hyper` 1.x for HTTP server
- Uses `hyper-util` for socket wrapping
- Uses `tokio` for async runtime
- Uses `parking_lot`, `serde_json`, `bytes` as utility crates

## Required State
Per selfhost's dependency policy (see `Cargo.toml` comments):
> Everything above the socket is written here: HTTP parsing, the reverse proxy, load balancing, health checking, Range handling, ACME, the DNS wire format, SMTP, and IMAP. If a protocol is on the wire, we own it.

The orchid image server **is on the wire** — it serves HTTP to VPN clients. Per policy, this should be implemented in-house.

## Solution
1. Write custom HTTP/1.1 server using only `tokio` (already in workspace)
2. Remove: `hyper`, `hyper-util`, `bytes`
3. Keep only: `tokio`, `serde_json` (for status JSON), `parking_lot` (efficient locks)
4. Implement:
   - TCP listener
   - HTTP request parsing (GET only, simple)
   - Response building with headers
   - JPEG body serving

## Scope
- [ ] Rewrite main.rs to use raw tokio TCP
- [ ] Remove hyper from Cargo.toml
- [ ] Test on Windows and Linux
- [ ] Add to deployment checklist

## Priority
LOW — Get working first, refactor after VPN integration complete.

## Timeline
After visual-entropy VPN auth is integrated and tested.
