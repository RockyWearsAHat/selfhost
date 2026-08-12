#!/usr/bin/env python3
"""Decode DNS questions out of a pktmon-produced pcapng, without libpcap.

Reads Enhanced Packet Blocks, walks Ethernet -> IPv4/IPv6 -> UDP/TCP:53, and
prints one line per DNS message: UTC time, direction, peer, and the question
asked. Written because macOS tcpdump refuses pktmon's pcapng snaplen and no
tshark exists on either machine.

Usage: dnsread.py <file.pcapng> [substring-filter]
"""

import struct
import sys
from datetime import datetime, timezone

QTYPE = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
         16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}


def read_blocks(data):
    """Yield (block_type, body) for every pcapng block in `data`."""
    off = 0
    endian = "<"
    while off + 12 <= len(data):
        btype, blen = struct.unpack_from(endian + "II", data, off)
        if btype == 0x0A0D0D0A:  # section header: byte order magic decides
            magic = struct.unpack_from("<I", data, off + 8)[0]
            endian = "<" if magic == 0x1A2B3C4D else ">"
            btype, blen = struct.unpack_from(endian + "II", data, off)
        if blen < 12 or off + blen > len(data):
            return
        yield btype, data[off + 8:off + blen - 4], endian
        off += blen


def qname(msg, off):
    """Return (name, next_offset) for the DNS name at `off`, following pointers."""
    labels, hops = [], 0
    while off < len(msg):
        n = msg[off]
        if n == 0:
            return ".".join(labels), off + 1
        if n & 0xC0 == 0xC0:  # compression pointer
            ptr = ((n & 0x3F) << 8) | msg[off + 1]
            hops += 1
            if hops > 8:
                break
            sub, _ = qname(msg, ptr)
            labels.append(sub)
            return ".".join(labels), off + 2
        labels.append(msg[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    return ".".join(labels), off


def dns_lines(pkt, ts, out, needle):
    """Append a printable line to `out` if `pkt` carries a DNS message."""
    if len(pkt) < 34:
        return
    ethertype = struct.unpack_from(">H", pkt, 12)[0]
    off = 14
    if ethertype == 0x8100:  # VLAN tag
        ethertype = struct.unpack_from(">H", pkt, 16)[0]
        off = 18
    if ethertype == 0x0800:
        ihl = (pkt[off] & 0x0F) * 4
        proto = pkt[off + 9]
        src = ".".join(str(b) for b in pkt[off + 12:off + 16])
        dst = ".".join(str(b) for b in pkt[off + 16:off + 20])
        off += ihl
    elif ethertype == 0x86DD:
        proto = pkt[off + 6]
        src = bytes(pkt[off + 8:off + 24]).hex(":", 2)
        dst = bytes(pkt[off + 24:off + 40]).hex(":", 2)
        off += 40
    else:
        return
    if proto == 17:
        sport, dport = struct.unpack_from(">HH", pkt, off)
        msg = pkt[off + 8:]
    elif proto == 6:
        sport, dport = struct.unpack_from(">HH", pkt, off)
        doff = (pkt[off + 12] >> 4) * 4
        msg = pkt[off + doff + 2:]  # TCP DNS carries a 2-byte length prefix
    else:
        return
    if 53 not in (sport, dport) or len(msg) < 13:
        return
    flags, qdcount = struct.unpack_from(">HH", msg, 2)
    if qdcount < 1:
        return
    name, end = qname(msg, 12)
    qtype = struct.unpack_from(">H", msg, end)[0] if end + 2 <= len(msg) else 0
    query = (flags & 0x8000) == 0
    peer = f"{src}:{sport}" if query else f"{dst}:{dport}"
    line = (f"{ts} {'Q' if query else 'R':1} {peer:<24} "
            f"{QTYPE.get(qtype, qtype)} {name}")
    if needle is None or needle.lower() in line.lower():
        out.append(line)


def main():
    path = sys.argv[1]
    needle = sys.argv[2] if len(sys.argv) > 2 else None
    data = open(path, "rb").read()
    out = []
    for btype, body, endian in read_blocks(data):
        if btype != 6:  # enhanced packet block
            continue
        _, tsh, tsl, caplen, _ = struct.unpack_from(endian + "IIIII", body, 0)
        micros = (tsh << 32) | tsl
        ts = datetime.fromtimestamp(micros / 1e6, timezone.utc).strftime("%H:%M:%SZ")
        dns_lines(body[20:20 + caplen], ts, out, needle)
    print("\n".join(out) if out else "(no DNS messages matched)")
    print(f"-- {len(out)} line(s) from {path}")


if __name__ == "__main__":
    main()
