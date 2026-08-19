#!/usr/bin/env python3
"""Calibrate the home application's colour pipeline for a WiZ bulb family.

The colour translation in crates/services/home/src/color.rs rests on one
measured object: the LED basis — what each of the bulb's LED channels alone
looks like to a camera, photographed off a sheet of white paper. This script
measures that basis for YOUR bulbs and prints the Rust constants block, so a
household with a different bulb family than ESP25_SHRGB_01 can be calibrated
in about five minutes with no other instrument than a laptop webcam.

Setup (the script walks you through it):
  1. A sheet of plain white paper on a surface lit by ONE of your bulbs,
     close enough that the bulb clearly lights it.
  2. Your laptop's camera pointed at the paper, filling most of the frame.
     Kill other coloured light in the room if you can; ordinary ambient is
     handled by a dark frame.
  3. Run:  python3 scripts/home/calibrate.py
     Every frame is captured automatically; you just leave the scene alone.

What it measures, in order:
  - a dark frame (all bulbs off) — the ambient the maths subtracts
  - each LED channel alone (red, green, blue, cold white) at full duty
  - the red channel at half and quarter duty — the PWM under-emission curve
  - a verification sweep: six colours through the computed pipeline,
    measured back off the paper, reported as chromatic error

Output: the `BASIS`, `BASIS_INV` and `PWM` constants for color.rs, plus the
module family name they belong to, and a JSON copy beside this script.

Requires: python3, numpy, ffmpeg. macOS's default camera is used unless
--camera / --capture-cmd say otherwise (see --help for a Linux example).
"""
import argparse, json, math, pathlib, shutil, socket, subprocess, sys, time

try:
    import numpy as np
except ImportError:
    sys.exit("numpy is needed: python3 -m pip install numpy")

PORT = 38899

# ── talking to bulbs ────────────────────────────────────────────────────────

def send(ip, payload, timeout=2.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.sendto(json.dumps(payload).encode(), (ip, PORT))
    try:
        data, _ = s.recvfrom(4096)
        return json.loads(data.decode("utf-8", "replace"))
    except socket.timeout:
        return {}
    finally:
        s.close()

def discover(timeout=3.0):
    msg = json.dumps({"method": "getPilot", "params": {}}).encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.settimeout(0.4)
    s.sendto(msg, ("255.255.255.255", PORT))
    found, end = set(), time.time() + timeout
    while time.time() < end:
        try:
            _, src = s.recvfrom(4096)
            found.add(src[0])
        except socket.timeout:
            continue
    s.close()
    return sorted(found)

def set_state(ip, **params):
    send(ip, {"method": "setPilot", "params": dict(state=True, **params)})

def off(ip):
    send(ip, {"method": "setPilot", "params": {"state": False}})

# ── the camera as a colorimeter ─────────────────────────────────────────────

def capture(args, name):
    if args.capture_cmd:
        subprocess.run(args.capture_cmd.replace("{out}", name), shell=True, check=True, timeout=30)
        return
    subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error",
                    "-f", "avfoundation", "-framerate", "30", "-video_size", "1280x720",
                    "-pixel_format", "nv12", "-i", args.camera,
                    "-vf", "select='gte(n,20)'", "-frames:v", "1", "-y", name],
                   check=True, timeout=30)

def paper_rgb(name):
    """Mean linear RGB of the paper: the bright-but-unclipped band of the frame."""
    raw = subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-i", name,
                          "-f", "rawvideo", "-pix_fmt", "rgb24", "-"],
                         capture_output=True, check=True).stdout
    pixels = len(raw) // 3
    img = np.frombuffer(raw, np.uint8)[: pixels * 3].reshape(-1, 3).astype(float)
    v = img.max(axis=1)
    lo, hi = np.percentile(v, 60), np.percentile(v, 95)
    sel = img[(v >= lo) & (v <= hi) & (v < 250)]
    return (sel.mean(axis=0) / 255.0) ** 2.2

def measure(args, bulb, label, params, workdir):
    if params is None:
        off(bulb)
    else:
        set_state(bulb, **params)
    time.sleep(args.settle)
    name = str(workdir / f"cal_{label}.jpg")
    capture(args, name)
    reading = paper_rgb(name)
    print(f"    {label:12} linear rgb ({reading[0]:.4f}, {reading[1]:.4f}, {reading[2]:.4f})")
    return reading

# ── the calibration itself ──────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bulb", help="IP of the bulb lighting the paper (default: you pick from a list)")
    ap.add_argument("--camera", default="FaceTime HD Camera", help="avfoundation camera name (macOS)")
    ap.add_argument("--capture-cmd", help="alternative capture command with {out} placeholder, e.g. "
                    "'ffmpeg -f v4l2 -i /dev/video0 -frames:v 1 -y {out}' on Linux")
    ap.add_argument("--dim", type=int, default=60, help="dimming used for every measurement (default 60)")
    ap.add_argument("--settle", type=float, default=2.5, help="seconds to wait after each set (default 2.5)")
    ap.add_argument("--skip-verify", action="store_true", help="skip the six-colour verification sweep")
    args = ap.parse_args()

    if not args.capture_cmd and not shutil.which("ffmpeg"):
        sys.exit("ffmpeg is needed for the camera: brew install ffmpeg")

    print("Discovering bulbs…")
    bulbs = discover()
    if not bulbs:
        sys.exit("No WiZ bulbs answered the broadcast. Are they powered and on this network?")
    print(f"  found {len(bulbs)}: {', '.join(bulbs)}")

    bulb = args.bulb
    if bulb is None:
        if len(bulbs) == 1:
            bulb = bulbs[0]
        else:
            print("\nWhich bulb lights the paper? Each will flash green in turn.")
            for i, ip in enumerate(bulbs):
                set_state(ip, r=0, g=255, b=0, dimming=100)
                answer = input(f"  is it {ip}, flashing now? [y/N] ").strip().lower()
                off(ip)
                if answer == "y":
                    bulb = ip
                    break
            if bulb is None:
                sys.exit("None chosen — rerun with --bulb <ip>.")

    module = send(bulb, {"method": "getSystemConfig", "params": {}}).get("result", {}).get("moduleName", "unknown")
    print(f"\nCalibrating {bulb} (module {module}). Others go dark during measurement.")
    for ip in bulbs:
        if ip != bulb:
            off(ip)

    input("\nPaper under the bulb, camera on the paper, scene still? Press Enter to start. ")
    workdir = pathlib.Path(__file__).resolve().parent / "calibration-frames"
    workdir.mkdir(exist_ok=True)
    d = args.dim

    print("\n  Measuring the LED basis:")
    dark = measure(args, bulb, "dark", None, workdir)
    R = measure(args, bulb, "red", dict(r=255, g=0, b=0, c=0, w=0, dimming=d), workdir)
    G = measure(args, bulb, "green", dict(r=0, g=255, b=0, c=0, w=0, dimming=d), workdir)
    B = measure(args, bulb, "blue", dict(r=0, g=0, b=255, c=0, w=0, dimming=d), workdir)
    C = measure(args, bulb, "white", dict(r=0, g=0, b=0, c=255, w=0, dimming=d), workdir)

    print("\n  Measuring the PWM curve (red at half and quarter duty):")
    Rh = measure(args, bulb, "red-half", dict(r=128, g=0, b=0, c=0, w=0, dimming=d), workdir)
    Rq = measure(args, bulb, "red-quarter", dict(r=64, g=0, b=0, c=0, w=0, dimming=d), workdir)

    # White-referenced basis. The camera's white balance and the paper's own
    # tint divide out; the camera's channel crosstalk stays in the matrix and
    # cancels in the solve, which is the trick that makes a webcam enough.
    M = np.column_stack([R / C, G / C, B / C])
    if abs(np.linalg.det(M)) < 1e-3:
        sys.exit("The basis is singular — a channel photographed dark? Check the scene and rerun.")
    MI = np.linalg.inv(M)

    # PWM: light emitted at duty f is f^p of full; p from the two part-duty frames.
    full = max(R[0] - dark[0], 1e-6)
    ps = []
    for duty, reading in ((128 / 255, Rh), (64 / 255, Rq)):
        frac = max(reading[0] - dark[0], 1e-6) / full
        if 0 < frac < 1:
            ps.append(math.log(frac) / math.log(duty))
    p = sum(ps) / len(ps) if ps else 1.224
    pwm = 1.0 / p
    print(f"\n  PWM: light = duty^{p:.3f}  (duty = light^{pwm:.3f}; fits agreed to "
          f"{100 * (max(ps) - min(ps)) / p:.1f}%)" if len(ps) == 2 else f"\n  PWM exponent: {pwm:.3f}")

    if not args.skip_verify:
        print("\n  Verification sweep — six colours through the computed pipeline:")
        Cw_dark = C - dark
        errors = []
        for hexstr in ["FF7300", "00FFBF", "0800FF", "A83232", "FFFF00", "FF00FF"]:
            t = np.array([(int(hexstr[i:i + 2], 16) / 255) ** 2.2 for i in (0, 2, 4)])
            L = np.clip(MI @ t, 0, None)
            peak = L.max()
            duty = [int(min(1.0, x / peak) ** pwm * 255 + 0.5) for x in L]
            level = int(max(10, min(100, peak * 100)))
            reading = measure(args, bulb, f"verify-{hexstr}",
                              dict(r=duty[0], g=duty[1], b=duty[2], c=0, w=0, dimming=level), workdir)
            achieved = np.clip((reading - dark), 1e-6, None) / np.clip(Cw_dark, 1e-6, None)
            want, got = t / t.max(), achieved / achieved.max()
            err = float(np.abs(want - got).max())
            errors.append(err)
            print(f"      {hexstr}: max channel error {err:.3f}")
        print(f"    median {np.median(errors):.3f}, worst {max(errors):.3f} "
              "(≤0.05 is a good calibration; ambient light and camera drift add noise)")

    set_state(bulb, r=255, g=255, b=255, c=0, w=0, dimming=d)

    print("\n─── paste into crates/services/home/src/color.rs (per-family constants) ───\n")
    print(f"// Measured for module family {module} on {time.strftime('%Y-%m-%d')} with scripts/home/calibrate.py")
    for name, matrix in (("BASIS", M), ("BASIS_INV", MI)):
        rows = ",\n    ".join("[" + ", ".join(repr(float(x)) for x in row) + "]" for row in matrix)
        print(f"const {name}: [[f64; 3]; 3] = [\n    {rows},\n];")
    print(f"const PWM: f64 = {pwm!r};")

    out = pathlib.Path(__file__).resolve().parent / f"calibration-{module}.json"
    out.write_text(json.dumps({"module": module, "bulb": bulb, "date": time.strftime("%Y-%m-%d"),
                               "basis": M.tolist(), "basis_inv": MI.tolist(), "pwm": pwm}, indent=2))
    print(f"\nSaved {out.name}. The frames are in {workdir.name}/ if you want to inspect them.")

if __name__ == "__main__":
    main()
