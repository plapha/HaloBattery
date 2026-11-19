"""Keychron mice on the 1K "Keychron Link" receiver (3434:d030), e.g. the M3 Mini.

The receiver's 1K mouse protocol, as Keychron Launcher (launcher.keychron.com) speaks it
over WebHID ("1k" receiver transceiver):

  * the vendor collection 008c:0001 on interface 1 (Windows calls it a bar code badge
    reader) takes 20-byte *feature* reports with report id 0x51;
  * request: feature report `51 06 00 ...` (command 06, device info);
  * 200 ms later the Launcher reads feature report 0x51 back:
    `51 06 <ver lo> <ver hi> <vid lo> <vid hi> <pid lo> <pid hi> <fw> <fw> <mode>
    <level> <state> ...`, with the paired mouse's own ids, the battery in percent, and
    `state & 3` nonzero while charging (the Launcher then shows a full bar, no level).

The request must go out at its own length (21 bytes with the report id). hidapi pads a
feature report to the collection's largest one (1001 bytes here), so this provider calls
HidD_SetFeature / HidD_GetFeature itself.

Read on real hardware: an M3 Mini (3434:d036) on 3434:d030 answered
`51 06 01 00 34 34 36 d0 04 01 09 63 00` (firmware 1.0.4, 99 %, not charging).
A read returns the receiver's last finished reply, and a request that arrives while it
is still busy with another command (Keychron Launcher's, say) is dropped: on hardware,
06 sent right after 07 kept reading back `51 07 ...`. So the request is sent up to three
times, 200 ms apart, until the reply is the device info. For the same reason a mouse
switched off after a reading can keep showing that level; the reply has no field that
tells the two apart.
"""
from __future__ import annotations

import ctypes
import sys
import time
from typing import List, Optional, Tuple

from . import hidlist
from .base import DeviceStatus, Provider, hexdump, log

VID = 0x3434
RECEIVERS = {0xD030: "Keychron Link"}
USAGE_PAGE, USAGE = 0x008C, 0x0001
REPORT_ID, CMD_INFO = 0x51, 0x06
REPORT_LEN = 21          # report id + 20 bytes, exactly as the Launcher sends it
WAIT_S = 0.2             # the Launcher reads the reply 200 ms after the request
ATTEMPTS = 3             # resend while the receiver was busy and dropped the request
MICE = {0xD036: "Keychron M3 Mini"}


def make_request() -> bytes:
    return bytes([REPORT_ID, CMD_INFO] + [0] * (REPORT_LEN - 2))


def parse_info(r) -> Optional[Tuple[int, bool, int]]:
    """(level, charging, mouse pid) from a device-info reply, or None."""
    if not r or len(r) < 13 or r[0] != REPORT_ID or r[1] != CMD_INFO:
        return None
    if (r[5] << 8 | r[4]) != VID:        # no paired mouse answering
        return None
    level = r[11]
    if not 0 <= level <= 100:
        return None
    return level, (r[12] & 3) != 0, r[7] << 8 | r[6]


def exchange(path) -> Optional[bytes]:
    """Send the request and read the reply; None off Windows. Raises OSError."""
    if sys.platform != "win32":
        return None
    p = path.decode("utf-8", "ignore") if isinstance(path, (bytes, bytearray)) else str(path)
    k32, hidd = ctypes.windll.kernel32, ctypes.windll.hid
    k32.CreateFileW.restype = ctypes.c_void_p
    handle = k32.CreateFileW(p, 0xC0000000, 3, None, 3, 0, None)
    if handle in (None, ctypes.c_void_p(-1).value):
        raise OSError(f"open failed ({k32.GetLastError()})")
    h = ctypes.c_void_p(handle)
    try:
        req = ctypes.create_string_buffer(make_request(), REPORT_LEN)
        for _ in range(ATTEMPTS):
            if not hidd.HidD_SetFeature(h, req, REPORT_LEN):
                raise OSError(f"HidD_SetFeature failed ({k32.GetLastError()})")
            time.sleep(WAIT_S)
            buf = ctypes.create_string_buffer(bytes([REPORT_ID]) + bytes(REPORT_LEN - 1), REPORT_LEN)
            if not hidd.HidD_GetFeature(h, buf, REPORT_LEN):
                raise OSError(f"HidD_GetFeature failed ({k32.GetLastError()})")
            if buf.raw[1] == CMD_INFO:
                break
        return buf.raw
    finally:
        k32.CloseHandle(h)


class KeychronLinkProvider(Provider):
    name = "keychron_link"

    def __init__(self):
        self._diag: List[str] = []

    def poll(self) -> List[DeviceStatus]:
        self._diag = []
        try:
            infos = hidlist.enumerate(VID)
        except Exception as e:  # pragma: no cover
            log.warning("hid.enumerate(keychron_link): %s", e)
            return []
        out = []
        for pid, receiver in RECEIVERS.items():
            mine = [d for d in infos if d.get("product_id") == pid
                    and (d.get("usage_page"), d.get("usage")) == (USAGE_PAGE, USAGE)]
            if not mine:
                continue
            d = mine[0]
            self._diag.append(f"[Keychron Link] pid={pid:04x} '{receiver}' "
                              f"iface={d.get('interface_number')} {USAGE_PAGE:04x}:{USAGE:04x}")
            try:
                r = exchange(d["path"])
            except OSError as e:
                self._diag.append(f"  {e}")
                continue
            if r is None:
                continue
            self._diag.append(f"  reply: {hexdump(r, 13)}")
            info = parse_info(r)
            if info is None:
                self._diag.append("  no device-info reply (mouse off, or another app is using the receiver)")
                continue
            level, charging, mouse = info
            name = MICE.get(mouse, f"Keychron mouse ({mouse:04x})")
            out.append(DeviceStatus(f"keychron_link:{pid:04x}", name, level, charging, True,
                                    self.name, kind="mouse"))
        return out

    def diagnostics(self) -> List[str]:
        return list(self._diag)
