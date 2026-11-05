#!/usr/bin/env python3
"""
keybridge.py - ultra-low-latency keyboard forwarding: macOS -> Windows.

One file, three modes:

  Windows : python keybridge.py receive --secret MYSECRET
  macOS   : python keybridge.py send    --host 192.168.1.50 --secret MYSECRET
  macOS   : python keybridge.py bench   --host 192.168.1.50 --secret MYSECRET

On the Mac, press  Ctrl + Option + Cmd + K  to toggle forwarding.
While forwarding is ON, keystrokes are swallowed on the Mac and typed on Windows.

Why it's fast
  * Captured with a Quartz CGEventTap (kernel-fed, no polling) and sent straight
    from the tap callback - no queues, no thread hand-offs.
  * Raw UDP, 20-byte packets, no Nagle / no TCP retransmit stalls / no TLS handshake.
  * Each key packet is sent twice (dedup'd by sequence number) so a dropped
    packet costs nothing instead of a retransmit timeout.
  * Windows side injects hardware scan codes with SendInput (layout-independent),
    from a HIGH_PRIORITY_CLASS process blocked in recvfrom (wakes instantly).
  * DSCP EF (expedited forwarding) marking for routers/APs that honour QoS.

Safety
  * Every packet is HMAC-SHA256 authenticated (truncated to 8 bytes) with your
    shared secret - other machines on the LAN cannot inject keystrokes.
  * Sequence numbers reject replays/duplicates within a session.
  * Heartbeat of currently-held keys every 200 ms; the receiver releases any key
    that the Mac no longer reports, and releases everything after 1 s of silence,
    so keys can never get stuck down.

Requirements
  macOS  : pip3 install pyobjc-framework-Quartz
           + grant your terminal "Accessibility" and "Input Monitoring"
             (System Settings > Privacy & Security).
  Windows: plain Python 3.8+, no packages. Allow UDP port 47800 in the firewall.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import socket
import statistics
import struct
import sys
import threading
import time

# --------------------------------------------------------------------------- #
# Protocol
# --------------------------------------------------------------------------- #
DEFAULT_PORT = 47800
TAG_LEN = 8
HDR = struct.Struct("!BBHII")      # type, flags, code, session, seq  -> 12 bytes
Q1 = struct.Struct("!Q")
Q3 = struct.Struct("!QQQ")

T_KEY, T_STATE, T_RELEASE_ALL, T_PING, T_PONG = 1, 2, 3, 4, 5
F_UP = 0x01
F_INJECT_TEST = 0x02

HEARTBEAT_S = 0.2
STALE_S = 1.0
EXT = 0xE000                       # "extended" (E0-prefixed) scan code marker
F24_SCAN = 0x76                    # harmless key used by bench --inject-test


class Sealer:
    """HMAC-SHA256 (truncated) authentication. ~1-2 us per packet."""

    def __init__(self, secret: str):
        key = hashlib.sha256(secret.encode("utf-8")).digest()
        self._base = hmac.new(key, digestmod=hashlib.sha256)

    def tag(self, body: bytes) -> bytes:
        h = self._base.copy()
        h.update(body)
        return h.digest()[:TAG_LEN]

    def seal(self, body: bytes) -> bytes:
        return body + self.tag(body)

    def open(self, data: bytes):
        if len(data) < HDR.size + TAG_LEN:
            return None
        body, tag = data[:-TAG_LEN], data[-TAG_LEN:]
        return body if hmac.compare_digest(tag, self.tag(body)) else None


class SeqGuard:
    """Accept each (session, seq) once and only in increasing order."""

    def __init__(self, max_sessions: int = 64):
        self.last = {}
        self.max_sessions = max_sessions

    def accept(self, session: int, seq: int) -> bool:
        last = self.last.get(session)
        if last is None:
            if len(self.last) >= self.max_sessions:
                self.last.pop(next(iter(self.last)))
            self.last[session] = seq
            return True
        if seq <= last:
            return False
        self.last[session] = seq
        return True


# --------------------------------------------------------------------------- #
# macOS virtual keycode  ->  Windows set-1 scan code
# --------------------------------------------------------------------------- #
_BASE_MAP = {
    # letters
    0x00: 0x1E, 0x0B: 0x30, 0x08: 0x2E, 0x02: 0x20, 0x0E: 0x12, 0x03: 0x21,  # A B C D E F
    0x05: 0x22, 0x04: 0x23, 0x22: 0x17, 0x26: 0x24, 0x28: 0x25, 0x25: 0x26,  # G H I J K L
    0x2E: 0x32, 0x2D: 0x31, 0x1F: 0x18, 0x23: 0x19, 0x0C: 0x10, 0x0F: 0x13,  # M N O P Q R
    0x01: 0x1F, 0x11: 0x14, 0x20: 0x16, 0x09: 0x2F, 0x0D: 0x11, 0x07: 0x2D,  # S T U V W X
    0x10: 0x15, 0x06: 0x2C,                                                  # Y Z
    # number row
    0x12: 0x02, 0x13: 0x03, 0x14: 0x04, 0x15: 0x05, 0x17: 0x06,              # 1-5
    0x16: 0x07, 0x1A: 0x08, 0x1C: 0x09, 0x19: 0x0A, 0x1D: 0x0B,              # 6-0
    0x1B: 0x0C, 0x18: 0x0D,                                                  # - =
    # punctuation
    0x21: 0x1A, 0x1E: 0x1B, 0x2A: 0x2B, 0x29: 0x27, 0x27: 0x28,              # [ ] \ ; '
    0x2B: 0x33, 0x2F: 0x34, 0x2C: 0x35,                                      # , . /
    0x32: 0x29,                        # ` (ANSI top-left)
    0x0A: 0x56,                        # ISO section key (102nd key)
    # editing / whitespace
    0x24: 0x1C, 0x30: 0x0F, 0x31: 0x39, 0x33: 0x0E, 0x35: 0x01,              # Ret Tab Spc Bksp Esc
    0x75: EXT | 0x53,                  # Forward Delete -> Delete
    0x72: EXT | 0x52,                  # Help -> Insert
    0x73: EXT | 0x47, 0x77: EXT | 0x4F,                                      # Home End
    0x74: EXT | 0x49, 0x79: EXT | 0x51,                                      # PgUp PgDn
    0x7B: EXT | 0x4B, 0x7C: EXT | 0x4D, 0x7D: EXT | 0x50, 0x7E: EXT | 0x48,  # arrows
    # modifiers (Cmd/Ctrl may be swapped by build_keymap)
    0x38: 0x2A, 0x3C: 0x36,            # L/R Shift
    0x3A: 0x38, 0x3D: EXT | 0x38,      # L/R Option -> L/R Alt
    0x3B: 0x1D, 0x3E: EXT | 0x1D,      # L/R Control -> L/R Ctrl
    0x37: EXT | 0x5B, 0x36: EXT | 0x5C,  # L/R Command -> L/R Win
    0x39: 0x3A,                        # Caps Lock
    # function keys
    0x7A: 0x3B, 0x78: 0x3C, 0x63: 0x3D, 0x76: 0x3E, 0x60: 0x3F, 0x61: 0x40,  # F1-F6
    0x62: 0x41, 0x64: 0x42, 0x65: 0x43, 0x6D: 0x44, 0x67: 0x57, 0x6F: 0x58,  # F7-F12
    0x69: 0x64, 0x6B: 0x65, 0x71: 0x66, 0x6A: 0x67, 0x40: 0x68, 0x4F: 0x69,  # F13-F18
    0x50: 0x6A, 0x5A: 0x6B,                                                  # F19 F20
    # keypad
    0x52: 0x52, 0x53: 0x4F, 0x54: 0x50, 0x55: 0x51, 0x56: 0x4B,              # KP0-4
    0x57: 0x4C, 0x58: 0x4D, 0x59: 0x47, 0x5B: 0x48, 0x5C: 0x49,              # KP5-9
    0x41: 0x53, 0x43: 0x37, 0x45: 0x4E, 0x4E: 0x4A, 0x4B: EXT | 0x35,        # . * + - /
    0x4C: EXT | 0x1C, 0x51: 0x59, 0x47: 0x45,                                # Enter = Clear->NumLock
    # media keys that arrive as keycodes on external keyboards
    0x48: EXT | 0x30, 0x49: EXT | 0x2E, 0x4A: EXT | 0x20,                    # Vol+ Vol- Mute
    # JIS
    0x5D: 0x7D, 0x5E: 0x73, 0x66: 0x7B, 0x68: 0x70,
}


def build_keymap(cmd_as_ctrl: bool = False, iso: bool = False) -> dict:
    m = dict(_BASE_MAP)
    if cmd_as_ctrl:  # Mac muscle memory: Cmd+C -> Ctrl+C ; Control -> Win
        m[0x37], m[0x36] = 0x1D, EXT | 0x1D
        m[0x3B], m[0x3E] = EXT | 0x5B, EXT | 0x5C
    if iso:          # ISO Macs report the two keys swapped vs. their position
        m[0x0A], m[0x32] = 0x29, 0x56
    return m


# Device-dependent modifier bits (NX_DEVICE*KEYMASK) - tell left from right.
MOD_MASKS = {0x3B: 0x1, 0x38: 0x2, 0x3C: 0x4, 0x37: 0x8,
             0x36: 0x10, 0x3A: 0x20, 0x3D: 0x40, 0x3E: 0x2000}
MAC_CAPS = 0x39
HOTKEY_KC = 0x28                                  # K
HOT_FLAGS = 0x40000 | 0x80000 | 0x100000          # Control | Option | Command


# --------------------------------------------------------------------------- #
# Sender core (OS-independent: used by `send` and `bench`)
# --------------------------------------------------------------------------- #
class Link:
    def __init__(self, host: str, port: int, secret: str, redundancy: int = 2):
        self.sealer = Sealer(secret)
        self.session = int.from_bytes(os.urandom(4), "big")
        self.seq = 0
        self.redundancy = max(1, redundancy)
        self.held = set()
        self._lock = threading.Lock()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 0xB8)  # DSCP EF
        except OSError:
            pass
        self.sock.connect((socket.gethostbyname(host), port))

    def _send(self, typ, flags, code, payload=b"", copies=None):
        with self._lock:
            self.seq = (self.seq + 1) & 0xFFFFFFFF
            pkt = self.sealer.seal(HDR.pack(typ, flags, code, self.session, self.seq) + payload)
        for _ in range(copies or self.redundancy):
            try:
                self.sock.send(pkt)
            except OSError:      # receiver not up yet (ICMP refused) etc.
                pass
        return pkt

    def key(self, code: int, up: bool):
        self._send(T_KEY, F_UP if up else 0, code)
        if up:
            self.held.discard(code)
        else:
            self.held.add(code)

    def state(self):
        codes = tuple(self.held)
        self._send(T_STATE, 0, len(codes), struct.pack("!%dH" % len(codes), *codes), copies=1)

    def release_all(self):
        self.held.clear()
        self._send(T_RELEASE_ALL, 0, 0, copies=3)


# --------------------------------------------------------------------------- #
# macOS: capture
# --------------------------------------------------------------------------- #
def run_sender(args):
    if sys.platform != "darwin":
        sys.exit("`send` must run on macOS.")
    try:
        import Quartz
    except ImportError:
        sys.exit("Missing dependency:  pip3 install pyobjc-framework-Quartz")

    keymap = build_keymap(args.cmd_as_ctrl, args.iso)
    link = Link(args.host, args.port, args.secret, args.redundancy)
    st = {"active": False, "hot_up": False, "passthru": set()}

    get_field = Quartz.CGEventGetIntegerValueField
    get_flags = Quartz.CGEventGetFlags
    KC_FIELD = Quartz.kCGKeyboardEventKeycode
    REP_FIELD = Quartz.kCGKeyboardEventAutorepeat
    KD, KU, FC = Quartz.kCGEventKeyDown, Quartz.kCGEventKeyUp, Quartz.kCGEventFlagsChanged
    DISABLED = (Quartz.kCGEventTapDisabledByTimeout, Quartz.kCGEventTapDisabledByUserInput)
    tap_ref = [None]

    def set_active(on: bool, flags: int):
        st["active"] = on
        if on:
            # modifiers held for the hotkey: let their key-ups go to the Mac
            st["passthru"] = {kc for kc, m in MOD_MASKS.items() if flags & m}
            print("▶  forwarding ON   (Ctrl+Option+Cmd+K to stop)", flush=True)
        else:
            link.release_all()
            print("■  forwarding OFF  (Ctrl+C here to quit)", flush=True)

    def callback(proxy, etype, event, refcon):
        try:
            if etype == KD or etype == KU:
                kc = get_field(event, KC_FIELD)
                if kc == HOTKEY_KC:
                    if etype == KD and (get_flags(event) & HOT_FLAGS) == HOT_FLAGS:
                        if not get_field(event, REP_FIELD):
                            set_active(not st["active"], get_flags(event))
                        st["hot_up"] = True
                        return None
                    if etype == KU and st["hot_up"]:
                        st["hot_up"] = False
                        return None
                if not st["active"]:
                    return event
                code = keymap.get(kc)
                if code is not None:
                    link.key(code, etype == KU)   # autorepeat downs forwarded too
                return None

            if etype == FC:
                if not st["active"]:
                    return event
                kc = get_field(event, KC_FIELD)
                if kc == MAC_CAPS:                 # macOS reports caps as a toggle
                    code = keymap[MAC_CAPS]
                    link.key(code, False)
                    link.key(code, True)
                    return None
                mask = MOD_MASKS.get(kc)
                if mask is None:                   # fn / globe key etc.
                    return event
                down = bool(get_flags(event) & mask)
                if kc in st["passthru"] and not down:
                    st["passthru"].discard(kc)
                    return event
                link.key(keymap[kc], not down)
                return None

            if etype in DISABLED and tap_ref[0] is not None:
                Quartz.CGEventTapEnable(tap_ref[0], True)
        except Exception as exc:  # never let an exception eat the keyboard
            print("callback error:", exc, file=sys.stderr)
        return event

    def heartbeat():
        while True:
            time.sleep(HEARTBEAT_S)
            if st["active"]:
                link.state()

    threading.Thread(target=heartbeat, daemon=True).start()

    mask = (1 << KD) | (1 << KU) | (1 << FC)
    tap = Quartz.CGEventTapCreate(Quartz.kCGSessionEventTap, Quartz.kCGHeadInsertEventTap,
                                  Quartz.kCGEventTapOptionDefault, mask, callback, None)
    if tap is None:
        sys.exit("Could not create event tap. Give your terminal app 'Accessibility' and "
                 "'Input Monitoring' permission (System Settings > Privacy & Security), "
                 "then restart the terminal.")
    tap_ref[0] = tap
    src = Quartz.CFMachPortCreateRunLoopSource(None, tap, 0)
    Quartz.CFRunLoopAddSource(Quartz.CFRunLoopGetCurrent(), src, Quartz.kCFRunLoopCommonModes)
    Quartz.CGEventTapEnable(tap, True)

    print(f"keybridge sender -> {args.host}:{args.port}  "
          f"(Cmd->{'Ctrl' if args.cmd_as_ctrl else 'Win'}, redundancy x{link.redundancy})")
    print("Press Ctrl+Option+Cmd+K to start forwarding.", flush=True)
    try:
        while True:
            Quartz.CFRunLoopRunInMode(Quartz.kCFRunLoopDefaultMode, 0.5, False)
    except KeyboardInterrupt:
        link.release_all()
        print("\nbye")


# --------------------------------------------------------------------------- #
# Windows: inject
# --------------------------------------------------------------------------- #
class WinInjector:
    """SendInput with hardware scan codes; INPUT struct pre-allocated."""

    def __init__(self):
        import ctypes
        from ctypes import wintypes

        ULONG_PTR = ctypes.c_size_t

        class KEYBDINPUT(ctypes.Structure):
            _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD),
                        ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD),
                        ("dwExtraInfo", ULONG_PTR)]

        class MOUSEINPUT(ctypes.Structure):
            _fields_ = [("dx", wintypes.LONG), ("dy", wintypes.LONG),
                        ("mouseData", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                        ("time", wintypes.DWORD), ("dwExtraInfo", ULONG_PTR)]

        class HARDWAREINPUT(ctypes.Structure):
            _fields_ = [("uMsg", wintypes.DWORD), ("wParamL", wintypes.WORD),
                        ("wParamH", wintypes.WORD)]

        class _U(ctypes.Union):
            _fields_ = [("ki", KEYBDINPUT), ("mi", MOUSEINPUT), ("hi", HARDWAREINPUT)]

        class INPUT(ctypes.Structure):
            _anonymous_ = ("u",)
            _fields_ = [("type", wintypes.DWORD), ("u", _U)]

        user32 = ctypes.WinDLL("user32", use_last_error=True)
        self._send = user32.SendInput
        self._send.argtypes = (wintypes.UINT, ctypes.POINTER(INPUT), ctypes.c_int)
        self._send.restype = wintypes.UINT
        self._inp = INPUT(type=1)              # INPUT_KEYBOARD
        self._ki = self._inp.ki
        self._ptr = ctypes.pointer(self._inp)
        self._size = ctypes.sizeof(INPUT)

        k32 = ctypes.WinDLL("kernel32")
        k32.GetCurrentProcess.restype = wintypes.HANDLE
        k32.GetCurrentThread.restype = wintypes.HANDLE
        k32.SetPriorityClass.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        k32.SetThreadPriority.argtypes = (wintypes.HANDLE, ctypes.c_int)
        k32.SetPriorityClass(k32.GetCurrentProcess(), 0x80)      # HIGH_PRIORITY_CLASS
        k32.SetThreadPriority(k32.GetCurrentThread(), 2)         # THREAD_PRIORITY_HIGHEST

    def key(self, code: int, up: bool):
        ki = self._ki
        ki.wScan = code & 0xFF
        # SCANCODE | EXTENDEDKEY? | KEYUP?
        ki.dwFlags = 0x8 | (0x1 if (code & 0xFF00) == EXT else 0) | (0x2 if up else 0)
        self._send(1, self._ptr, self._size)


class DryRunInjector:
    """Prints instead of typing - for testing on any OS."""

    def __init__(self, quiet: bool = False):
        self.quiet = quiet
        self.log = []

    def key(self, code: int, up: bool):
        self.log.append((code, bool(up)))
        if not self.quiet:
            print(f"  {'up  ' if up else 'down'} 0x{code:04X}", flush=True)


def serve(sock, sealer, inj, verbose=False, stop=None):
    guard = SeqGuard()
    held = set()
    last_rx = time.monotonic()
    perf = time.perf_counter_ns
    mono = time.monotonic

    def release_all():
        for c in list(held):
            inj.key(c, True)
        held.clear()

    while stop is None or not stop.is_set():
        try:
            data, addr = sock.recvfrom(2048)
        except socket.timeout:
            if held and mono() - last_rx > STALE_S:
                release_all()
                if verbose:
                    print("sender silent - released all keys")
            continue
        except (ConnectionResetError, OSError) as exc:
            if isinstance(exc, socket.timeout):
                continue
            if stop is not None and stop.is_set():
                break
            continue
        t_rx = perf()
        body = sealer.open(data)
        if body is None:
            continue
        typ, flags, code, sess, seq = HDR.unpack_from(body)
        if not guard.accept(sess, seq):
            continue

        if typ == T_KEY:                         # hot path: inject first
            up = flags & F_UP
            inj.key(code, up)
            if up:
                held.discard(code)
            else:
                held.add(code)
            last_rx = mono()
            if verbose:
                print(f"key 0x{code:04X} {'up' if up else 'down'}  {(perf()-t_rx)/1000:.1f} us")
        elif typ == T_STATE:
            n = code
            if len(body) < HDR.size + 2 * n:
                continue
            want = set(struct.unpack_from("!%dH" % n, body, HDR.size))
            for c in held - want:
                inj.key(c, True)
            held &= want
            last_rx = mono()
        elif typ == T_RELEASE_ALL:
            release_all()
            last_rx = mono()
        elif typ == T_PING:
            (t_echo,) = Q1.unpack_from(body, HDR.size)
            inject_ns = 0
            if flags & F_INJECT_TEST:
                t0 = perf()
                inj.key(F24_SCAN, False)
                inj.key(F24_SCAN, True)
                inject_ns = (perf() - t0) // 2   # per key event
            proc_ns = perf() - t_rx
            pong = sealer.seal(HDR.pack(T_PONG, 0, 0, sess, seq) + Q3.pack(t_echo, inject_ns, proc_ns))
            try:
                sock.sendto(pong, addr)
            except OSError:
                pass


def run_receiver(args):
    if args.dry_run or os.name != "nt":
        if os.name != "nt" and not args.dry_run:
            print("Not on Windows - running in --dry-run mode (keys are printed).")
        inj = DryRunInjector()
    else:
        inj = WinInjector()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 16)
    sock.bind((args.bind, args.port))
    sock.settimeout(0.25)
    print(f"keybridge receiver listening on UDP {args.bind}:{args.port}  (Ctrl+C to quit)",
          flush=True)
    try:
        serve(sock, Sealer(args.secret), inj, verbose=args.verbose)
    except KeyboardInterrupt:
        print("\nbye")


# --------------------------------------------------------------------------- #
# Benchmark + report
# --------------------------------------------------------------------------- #
def _stats(xs_ns):
    xs = sorted(x / 1000.0 for x in xs_ns)          # -> microseconds
    if not xs:
        return None
    pct = lambda p: xs[min(len(xs) - 1, int(round(p * (len(xs) - 1))))]
    return {"min": xs[0], "median": statistics.median(xs), "mean": statistics.fmean(xs),
            "p95": pct(0.95), "p99": pct(0.99), "max": xs[-1]}


def _fmt(us):
    return f"{us/1000:.3f} ms" if us >= 1000 else f"{us:.1f} µs"


def run_bench(args):
    link = Link(args.host, args.port, args.secret, 1)
    link.sock.settimeout(args.timeout)
    sealer = link.sealer
    perf = time.perf_counter_ns

    # 1) local encode+authenticate cost per key packet
    n = 20000
    t0 = perf()
    for i in range(n):
        sealer.seal(HDR.pack(T_KEY, 0, 0x1E, 1, i))
    encode_ns = (perf() - t0) / n

    # 2) round trips
    rtts, procs, injects, lost = [], [], [], 0
    total = args.warmup + args.count
    print(f"Pinging {args.host}:{args.port}  x{args.count} (+{args.warmup} warm-up) ...", flush=True)
    for i in range(total):
        t_send = perf()
        link._send(T_PING, F_INJECT_TEST if args.inject_test else 0, 0, Q1.pack(t_send), copies=1)
        while True:
            try:
                data = link.sock.recv(2048)
            except (socket.timeout, ConnectionRefusedError, ConnectionResetError):
                if i >= args.warmup:
                    lost += 1
                break
            t_back = perf()
            body = sealer.open(data)
            if body is None:
                continue
            typ, _, _, sess, _ = HDR.unpack_from(body)
            if typ != T_PONG or sess != link.session:
                continue
            echo, inj_ns, proc_ns = Q3.unpack_from(body, HDR.size)
            if echo != t_send:
                continue                     # late pong from an earlier ping
            if i >= args.warmup:
                rtts.append(t_back - t_send)
                procs.append(proc_ns)
                if args.inject_test:
                    injects.append(inj_ns)
            break
        if args.interval:
            time.sleep(args.interval)

    rtt = _stats(rtts)
    if rtt is None:
        sys.exit("No replies. Is the receiver running, is the secret identical, "
                 "and is UDP %d allowed through the Windows firewall?" % args.port)
    proc = _stats(procs)
    oneway = _stats([max(0, r - p) / 2 for r, p in zip(rtts, procs)])
    inj = _stats(injects) if injects else None

    enc_us = encode_ns / 1000
    # receiver processing already contains the injection when --inject-test is used
    # (two key events), so this is a slightly conservative upper estimate.
    added_med = enc_us + oneway["median"] + proc["median"]
    added_p99 = enc_us + oneway["p99"] + proc["p99"]

    rows = [("Network round trip (RTT)", rtt), ("Network one-way (≈ RTT−proc ÷ 2)", oneway),
            ("Receiver processing", proc)]
    if inj:
        rows.append(("SendInput injection (per key)", inj))

    lines = [
        "# keybridge latency report", "",
        f"- Target: `{args.host}:{args.port}`  ·  samples: {len(rtts)}  ·  lost: {lost} "
        f"({100*lost/max(1,args.count):.2f} %)",
        f"- Date: {time.strftime('%Y-%m-%d %H:%M:%S')}  ·  host: {socket.gethostname()}  "
        f"·  Python {sys.version.split()[0]}", "",
        "| Stage | min | median | mean | p95 | p99 | max |",
        "|---|---|---|---|---|---|---|",
        f"| Mac encode + HMAC (per packet) | {_fmt(enc_us)} | {_fmt(enc_us)} | {_fmt(enc_us)} | – | – | – |",
    ]
    for name, s in rows:
        lines.append(f"| {name} | " + " | ".join(_fmt(s[k]) for k in
                     ("min", "median", "mean", "p95", "p99", "max")) + " |")
    lines += [
        "",
        "## Added latency vs. typing on a keyboard plugged into Windows", "",
        f"- **Typical (median): +{_fmt(added_med)}**",
        f"- **Worst 1 % (p99): +{_fmt(added_p99)}**",
        "",
        "Both paths share the same physical-keyboard cost (USB polling 1–8 ms + "
        "debounce), so these figures are the *extra* time keybridge adds: "
        "Mac encode → network one-way → Windows receive + SendInput."
        + ("" if inj else " Injection not measured – rerun with `--inject-test` "
           "(types the unused F24 key) to include it; it is usually < 50 µs."),
        "Not included: macOS event-tap delivery (kernel → tap callback), typically well under 1 ms.",
        "",
        "Tips if numbers are high: use Ethernet on both machines (Wi-Fi power-save adds "
        "multi-ms spikes), keep both on the same switch/AP, disable VPNs.",
    ]
    report = "\n".join(lines) + "\n"
    print("\n" + report)
    with open(args.report, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"Saved report to {os.path.abspath(args.report)}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv=None):
    p = argparse.ArgumentParser(description="Low-latency Mac -> Windows keyboard bridge")
    sub = p.add_subparsers(dest="mode", required=True)

    def common(sp):
        sp.add_argument("--secret", required=True, help="shared secret (same on both machines)")
        sp.add_argument("--port", type=int, default=DEFAULT_PORT)

    r = sub.add_parser("receive", help="run on Windows: inject received keys")
    common(r)
    r.add_argument("--bind", default="0.0.0.0")
    r.add_argument("--dry-run", action="store_true", help="print keys instead of typing")
    r.add_argument("--verbose", action="store_true")

    s = sub.add_parser("send", help="run on macOS: capture and forward keys")
    common(s)
    s.add_argument("--host", required=True, help="Windows machine IP")
    s.add_argument("--cmd-as-ctrl", action="store_true",
                   help="map Cmd->Ctrl and Control->Win (Mac shortcuts on Windows)")
    s.add_argument("--iso", action="store_true", help="ISO (European) Mac keyboard layout")
    s.add_argument("--redundancy", type=int, default=2, help="copies of each key packet")

    b = sub.add_parser("bench", help="measure latency to the receiver and write a report")
    common(b)
    b.add_argument("--host", required=True)
    b.add_argument("--count", type=int, default=2000)
    b.add_argument("--warmup", type=int, default=50)
    b.add_argument("--interval", type=float, default=0.005, help="seconds between pings")
    b.add_argument("--timeout", type=float, default=0.5)
    b.add_argument("--inject-test", action="store_true",
                   help="also measure SendInput by typing the unused F24 key")
    b.add_argument("--report", default="keybridge_report.md")

    args = p.parse_args(argv)
    {"receive": run_receiver, "send": run_sender, "bench": run_bench}[args.mode](args)


if __name__ == "__main__":
    main()