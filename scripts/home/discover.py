#!/usr/bin/env python3
"""One-shot LAN discovery: mDNS service types + instances, and SSDP/UPnP."""
import socket, struct, time, sys, collections

MDNS = ("224.0.0.251", 5353)

def encode_name(name):
    out = b""
    for label in name.split("."):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b"\x00"

def query(names):
    """Build one mDNS query packet asking PTR for several names."""
    hdr = struct.pack("!HHHHHH", 0, 0, len(names), 0, 0, 0)
    body = b"".join(encode_name(n) + struct.pack("!HH", 12, 1) for n in names)
    return hdr + body

def decode_name(buf, off):
    parts, jumped, safety = [], False, 0
    while safety < 128:
        safety += 1
        if off >= len(buf):
            break
        l = buf[off]
        if l == 0:
            off += 1
            break
        if l & 0xC0 == 0xC0:
            ptr = struct.unpack("!H", buf[off:off+2])[0] & 0x3FFF
            if not jumped:
                end = off + 2
            jumped = True
            off = ptr
            continue
        parts.append(buf[off+1:off+1+l].decode("utf-8", "replace"))
        off += 1 + l
    return ".".join(parts), (end if jumped else off)

def parse(buf):
    """Yield (name, rtype, rdata_name_or_bytes) for every record in a response."""
    try:
        qd, an, ns, ar = struct.unpack("!HHHH", buf[4:12])
    except Exception:
        return
    off = 12
    for _ in range(qd):
        _, off = decode_name(buf, off)
        off += 4
    for _ in range(an + ns + ar):
        if off >= len(buf):
            return
        name, off = decode_name(buf, off)
        if off + 10 > len(buf):
            return
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", buf[off:off+10])
        off += 10
        rdata = buf[off:off+rdlen]
        if rtype in (12, 33):  # PTR, SRV
            target, _ = decode_name(buf, off + (6 if rtype == 33 else 0))
            yield name, rtype, target
        elif rtype == 1 and rdlen == 4:  # A
            yield name, rtype, socket.inet_ntoa(rdata)
        elif rtype == 16:  # TXT
            yield name, rtype, rdata
        off += rdlen

def mdns_sweep(seconds=6.0, extra_names=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except Exception:
        pass
    s.bind(("", 5353))
    mreq = struct.pack("4sl", socket.inet_aton("224.0.0.251"), socket.INADDR_ANY)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    s.settimeout(0.5)

    names = ["_services._dns-sd._udp.local"] + (extra_names or [])
    for chunk in [names[i:i+8] for i in range(0, len(names), 8)]:
        try:
            s.sendto(query(chunk), MDNS)
        except Exception as e:
            print("send failed:", e, file=sys.stderr)

    types, instances, addrs, txts = set(), set(), {}, {}
    end = time.time() + seconds
    resend = time.time() + 2.0
    while time.time() < end:
        if time.time() > resend:
            for chunk in [names[i:i+8] for i in range(0, len(names), 8)]:
                try:
                    s.sendto(query(chunk), MDNS)
                except Exception:
                    pass
            resend = time.time() + 2.5
        try:
            data, src = s.recvfrom(9000)
        except socket.timeout:
            continue
        except Exception:
            continue
        for name, rtype, val in parse(data):
            if rtype == 12:
                if name == "_services._dns-sd._udp.local":
                    types.add(val)
                elif name.endswith("._tcp.local") or name.endswith("._udp.local"):
                    instances.add((name, val))
            elif rtype == 1:
                addrs[name] = val
            elif rtype == 16 and len(val) > 1:
                txts.setdefault(name, val[:400])
    s.close()
    return types, instances, addrs, txts

def ssdp(seconds=4.0):
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n').encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(0.5)
    try:
        s.sendto(msg, ("239.255.255.250", 1900))
    except Exception as e:
        return {}
    found = collections.defaultdict(set)
    end = time.time() + seconds
    while time.time() < end:
        try:
            data, src = s.recvfrom(4096)
        except socket.timeout:
            continue
        except Exception:
            continue
        text = data.decode("utf-8", "replace")
        server = location = st = ""
        for line in text.split("\r\n"):
            low = line.lower()
            if low.startswith("server:"):
                server = line[7:].strip()
            elif low.startswith("location:"):
                location = line[9:].strip()
            elif low.startswith("st:"):
                st = line[3:].strip()
        found[src[0]].add((server, location))
    s.close()
    return found

if __name__ == "__main__":
    # Ask for the well-known smart-home service types explicitly too: some
    # responders answer a direct question but not the meta-query.
    WANTED = [t + ".local" for t in [
        "_hap._tcp", "_homekit._tcp", "_matter._tcp", "_matterc._udp",
        "_airplay._tcp", "_raop._tcp", "_airport._tcp", "_companion-link._tcp",
        "_googlecast._tcp", "_spotify-connect._tcp", "_sonos._tcp",
        "_hue._tcp", "_philipshue._tcp", "_wled._tcp", "_shelly._tcp",
        "_esphomelib._tcp", "_tplink._tcp", "_kasa._tcp", "_ewelink._tcp",
        "_roku._tcp", "_androidtvremote2._tcp", "_viziocast._tcp",
        "_lg-smart-device._tcp", "_samsungmsf._tcp", "_smartview2._tcp",
        "_http._tcp", "_ipp._tcp", "_workstation._tcp", "_ssh._tcp",
        "_home-assistant._tcp", "_mqtt._tcp", "_dyson_mqtt._tcp",
        "_nanoleafapi._tcp", "_elg._tcp", "_lutron._tcp", "_bond._tcp",
        "_amzn-wplay._tcp", "_amzn-alexa._tcp", "_daap._tcp", "_touch-able._tcp",
    ]]
    types, instances, addrs, txts = mdns_sweep(9.0, WANTED)

    print("=" * 70)
    print("mDNS SERVICE TYPES ADVERTISED ON THIS LAN")
    print("=" * 70)
    for t in sorted(types):
        print("  ", t)
    if not types:
        print("   (none answered the meta-query)")

    print()
    print("=" * 70)
    print("mDNS SERVICE INSTANCES")
    print("=" * 70)
    by_type = collections.defaultdict(list)
    for svc, inst in instances:
        by_type[svc].append(inst)
    for svc in sorted(by_type):
        print(f"\n  {svc}")
        for inst in sorted(set(by_type[svc])):
            print(f"      {inst}")

    print()
    print("=" * 70)
    print("HOST -> ADDRESS")
    print("=" * 70)
    for h in sorted(addrs):
        print(f"  {h:55s} {addrs[h]}")

    print()
    print("=" * 70)
    print("TXT RECORDS (model / capability hints)")
    print("=" * 70)
    for h in sorted(txts):
        raw = txts[h]
        # TXT is length-prefixed strings
        out, i = [], 0
        while i < len(raw):
            l = raw[i]
            out.append(raw[i+1:i+1+l].decode("utf-8", "replace"))
            i += 1 + l
        joined = " | ".join(x for x in out if x)
        if joined:
            print(f"  {h}\n      {joined[:300]}")

    print()
    print("=" * 70)
    print("SSDP / UPnP")
    print("=" * 70)
    for ip, entries in sorted(ssdp(5.0).items()):
        print(f"  {ip}")
        for server, location in sorted(entries):
            print(f"      {server}")
            print(f"      {location}")
