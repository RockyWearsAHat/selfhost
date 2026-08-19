#!/usr/bin/env python3
"""Second-pass probe: enumerate every host on the /24, then ask the
non-mDNS smart-home protocols directly (Kasa, LIFX, Tuya, WiZ, Shelly, Hue)."""
import socket, struct, subprocess, time, json, re, sys
from concurrent.futures import ThreadPoolExecutor

SUBNET = "192.168.1"

# ---------- host sweep -------------------------------------------------------

def ping(host):
    r = subprocess.run(["ping", "-c", "1", "-W", "400", host],
                       capture_output=True)
    return host if r.returncode == 0 else None

def sweep():
    hosts = [f"{SUBNET}.{i}" for i in range(1, 255)]
    with ThreadPoolExecutor(max_workers=128) as ex:
        alive = [h for h in ex.map(ping, hosts) if h]
    return alive

def arp_table():
    out = subprocess.run(["arp", "-a"], capture_output=True, text=True).stdout
    table = {}
    for line in out.splitlines():
        m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]+)", line)
        if m and m.group(2) != "(incomplete)":
            table[m.group(1)] = m.group(2)
    return table

OUI = {
    "78:28:ca": "Sonos", "f0:f6:c1": "Sonos", "5c:aa:fd": "Sonos",
    "00:1b:a9": "Brother", "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi", "2c:cf:67": "Raspberry Pi",
    "00:17:88": "Philips Hue", "ec:b5:fa": "Philips Hue",
    "d0:73:d5": "LIFX", "68:ff:7b": "TP-Link", "1c:3b:f3": "TP-Link",
    "50:c7:bf": "TP-Link Kasa", "b0:be:76": "TP-Link", "ac:84:c6": "TP-Link",
    "22:a1:71": "Amazon (randomised)", "fc:65:de": "Amazon", "68:54:fd": "Amazon",
    "44:65:0d": "Amazon", "f0:81:73": "Amazon", "0c:47:c9": "Amazon",
    "a4:08:01": "Amazon", "74:c2:46": "Amazon", "b4:7c:9c": "Amazon",
    "8c:85:80": "Sercomm", "20:df:b9": "Google", "f4:f5:d8": "Google",
    "54:60:09": "Google", "d8:6c:63": "Google", "3c:5c:c4": "Espressif",
    "8c:aa:b5": "Espressif", "24:0a:c4": "Espressif", "a4:cf:12": "Espressif",
    "cc:50:e3": "Espressif", "84:cc:a8": "Espressif", "b4:e6:2d": "Espressif",
    "e8:db:84": "Espressif", "c8:2b:96": "Espressif", "34:94:54": "Espressif",
    "d4:d4:da": "Ubiquiti/Netgear", "9c:3d:cf": "Netgear", "a0:40:a0": "Netgear",
    "b0:39:56": "Netgear", "20:e5:2a": "Netgear", "cc:40:d0": "Netgear",
}

def vendor(mac):
    return OUI.get(mac[:8].lower(), "")

# ---------- protocol probes --------------------------------------------------

def kasa_discover(timeout=3.0):
    """TP-Link Kasa: UDP 9999, XOR autokey with initial key 171."""
    def encrypt(s):
        key, out = 171, bytearray()
        for c in s.encode():
            key ^= c
            out.append(key)
        return bytes(out)
    def decrypt(b):
        key, out = 171, bytearray()
        for c in b:
            out.append(key ^ c)
            key = c
        return out.decode("utf-8", "replace")
    payload = encrypt('{"system":{"get_sysinfo":{}}}')
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.settimeout(0.4)
    found = {}
    try:
        s.sendto(payload, ("255.255.255.255", 9999))
        s.sendto(payload, (f"{SUBNET}.255", 9999))
    except Exception as e:
        return {"error": str(e)}
    end = time.time() + timeout
    while time.time() < end:
        try:
            data, src = s.recvfrom(4096)
            found[src[0]] = decrypt(data)[:300]
        except socket.timeout:
            continue
        except Exception:
            break
    s.close()
    return found

def lifx_discover(timeout=3.0):
    """LIFX LAN protocol: GetService (type 2) broadcast to UDP 56700."""
    frame = struct.pack("<HHI", 36, 0x3400, 0)            # size, origin/tagged/proto, source
    frame += b"\x00" * 8                                   # target
    frame += b"\x00" * 6 + struct.pack("<BB", 0x01, 0)     # reserved, res_required/ack
    frame += struct.pack("<HH", 2, 0)                      # type=GetService
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.settimeout(0.4)
    found = set()
    try:
        s.sendto(frame, ("255.255.255.255", 56700))
    except Exception as e:
        return {"error": str(e)}
    end = time.time() + timeout
    while time.time() < end:
        try:
            _, src = s.recvfrom(1024)
            found.add(src[0])
        except socket.timeout:
            continue
        except Exception:
            break
    s.close()
    return sorted(found)

def wiz_discover(timeout=3.0):
    """WiZ: UDP 38899 registration broadcast."""
    msg = json.dumps({"method": "getPilot", "params": {}}).encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.settimeout(0.4)
    found = {}
    try:
        s.sendto(msg, ("255.255.255.255", 38899))
    except Exception as e:
        return {"error": str(e)}
    end = time.time() + timeout
    while time.time() < end:
        try:
            data, src = s.recvfrom(2048)
            found[src[0]] = data.decode("utf-8", "replace")[:200]
        except socket.timeout:
            continue
        except Exception:
            break
    s.close()
    return found

def tuya_listen(timeout=5.0):
    """Tuya devices beacon themselves on UDP 6666/6667 unprompted."""
    found = {}
    socks = []
    for port in (6666, 6667):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("", port))
            s.settimeout(0.4)
            socks.append(s)
        except Exception:
            pass
    end = time.time() + timeout
    while time.time() < end and socks:
        for s in socks:
            try:
                data, src = s.recvfrom(2048)
                found[src[0]] = data[:120].hex()
            except socket.timeout:
                continue
            except Exception:
                continue
    for s in socks:
        s.close()
    return found

def http_probe(host, port, path, timeout=1.5):
    try:
        with socket.create_connection((host, port), timeout=timeout) as c:
            c.settimeout(timeout)
            c.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                      f"Connection: close\r\nUser-Agent: selfhost-probe\r\n\r\n".encode())
            buf = b""
            while len(buf) < 8192:
                chunk = c.recv(4096)
                if not chunk:
                    break
                buf += chunk
            return buf.decode("utf-8", "replace")
    except Exception:
        return None

def identify(host):
    """Ask a live host the handful of questions that name a smart-home device."""
    hits = []
    probes = [
        (80,   "/shelly",            "Shelly"),
        (80,   "/api/config",        "generic"),
        (80,   "/description.xml",   "UPnP"),
        (80,   "/",                  "HTTP"),
        (8080, "/",                  "HTTP:8080"),
        (9080, "/",                  "HTTP:9080"),
        (1400, "/xml/device_description.xml", "Sonos"),
        (8008, "/setup/eureka_info", "Cast"),
        (8060, "/query/device-info", "Roku"),
        (9999, "/",                  "Kasa"),
        (55000,"/",                  "Samsung"),
        (3000, "/",                  "HTTP:3000"),
    ]
    for port, path, label in probes:
        r = http_probe(host, port, path)
        if r:
            first = r.split("\r\n")[0]
            server = ""
            m = re.search(r"(?im)^server:\s*(.+)$", r)
            if m:
                server = m.group(1).strip()
            title = ""
            m = re.search(r"(?is)<title>(.*?)</title>", r)
            if m:
                title = m.group(1).strip()[:80]
            m = re.search(r"(?is)<friendlyName>(.*?)</friendlyName>", r)
            if m:
                title = "friendlyName=" + m.group(1).strip()[:80]
            m = re.search(r"(?is)<modelName>(.*?)</modelName>", r)
            if m:
                title += " modelName=" + m.group(1).strip()[:60]
            body_hint = ""
            if '"' in r and label in ("Shelly", "Roku", "Cast"):
                body_hint = r[-300:].replace("\n", " ")[:200]
            hits.append(f"    :{port}{path} -> {first} | {server} | {title} {body_hint}".rstrip())
    return hits

# ---------- main -------------------------------------------------------------

if __name__ == "__main__":
    print("sweeping the /24 ...", file=sys.stderr)
    alive = sweep()
    arp = arp_table()

    print("=" * 78)
    print("LIVE HOSTS")
    print("=" * 78)
    for h in sorted(alive, key=lambda x: int(x.split(".")[-1])):
        mac = arp.get(h, "")
        print(f"  {h:16s} {mac:20s} {vendor(mac) if mac else ''}")

    print()
    print("=" * 78)
    print("TP-Link Kasa (UDP 9999 broadcast)")
    print("=" * 78)
    print(" ", kasa_discover() or "(nothing answered)")

    print()
    print("=" * 78)
    print("LIFX (UDP 56700 broadcast)")
    print("=" * 78)
    print(" ", lifx_discover() or "(nothing answered)")

    print()
    print("=" * 78)
    print("WiZ (UDP 38899 broadcast)")
    print("=" * 78)
    print(" ", wiz_discover() or "(nothing answered)")

    print()
    print("=" * 78)
    print("Tuya beacons (UDP 6666/6667, passive)")
    print("=" * 78)
    print(" ", tuya_listen() or "(nothing beaconed)")

    print()
    print("=" * 78)
    print("PER-HOST HTTP IDENTIFICATION")
    print("=" * 78)
    with ThreadPoolExecutor(max_workers=16) as ex:
        results = list(ex.map(identify, alive))
    for h, hits in zip(alive, results):
        if hits:
            print(f"\n  {h}  [{vendor(arp.get(h,'')) or arp.get(h,'')}]")
            for line in hits:
                print(line)
