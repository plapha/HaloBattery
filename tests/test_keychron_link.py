"""Keychron Link 1K receiver (3434:d030): device-info reply, collection choice, failures."""
import ctypes
import types
import unittest
from unittest import mock

from providers import keychron_link as K

# M3 Mini (3434:d036) on 3434:d030, read on real hardware: firmware 1.0.4, 99 %, not charging
CAPTURE = bytes.fromhex("51 06 01 00 34 34 36 d0 04 01 09 63 00" + " 00" * 8)
REAL_EXCHANGE = K.exchange
# the reply to an earlier command 07, still in the receiver when 06 was read (seen on hardware)
STALE_07 = bytes.fromhex("51 07 00 23 23 03 90 01 20 03 34 08 80") + bytes(8)


def entry(**changes):
    result = {"vendor_id": K.VID, "product_id": 0xD030, "interface_number": 1,
              "usage_page": K.USAGE_PAGE, "usage": K.USAGE, "path": b"link-8c"}
    result.update(changes)
    return result


class ReplyTests(unittest.TestCase):
    def test_real_m3_mini_capture(self):
        self.assertEqual(K.parse_info(CAPTURE), (99, False, 0xD036))

    def test_nonzero_state_is_charging(self):
        for state in (1, 2, 3):
            reply = bytearray(CAPTURE)
            reply[12] = state
            self.assertEqual(K.parse_info(reply), (99, True, 0xD036))

    def test_other_reports_commands_vendors_and_levels_are_ignored(self):
        for index, value in ((0, 0x52), (1, 0x61), (1, 0x07), (4, 0x00), (5, 0x00), (11, 101), (11, 255)):
            with self.subTest(index=index, value=value):
                reply = bytearray(CAPTURE)
                reply[index] = value
                self.assertIsNone(K.parse_info(reply))

    def test_stale_reply_of_another_command_is_ignored(self):
        # what the receiver returned while Keychron Launcher's last command was 52 61
        self.assertIsNone(K.parse_info(bytes.fromhex("52 61") + bytes(19)))

    def test_short_or_empty_replies_are_ignored(self):
        for size in range(13):
            self.assertIsNone(K.parse_info(CAPTURE[:size]))
        self.assertIsNone(K.parse_info(None))

    def test_request_is_sent_at_its_own_length(self):
        self.assertEqual(K.make_request(), bytes([0x51, 0x06]) + bytes(19))
        self.assertEqual(len(K.make_request()), K.REPORT_LEN)


class PollTests(unittest.TestCase):
    def setUp(self):
        self.entries = [entry(),
                        entry(usage_page=1, usage=4, path=b"link-gamepad"),
                        entry(interface_number=3, usage_page=0xFF60, usage=0x61, path=b"link-via"),
                        entry(interface_number=0, usage_page=1, usage=2, path=b"link-mouse")]
        self.reply = CAPTURE
        self.paths = []

        def fake_exchange(path):
            self.paths.append(path)
            if isinstance(self.reply, Exception):
                raise self.reply
            return self.reply
        for patch in (mock.patch.object(K.hidlist, "enumerate", side_effect=lambda vid: self.entries),
                      mock.patch.object(K, "exchange", side_effect=fake_exchange)):
            patch.start()
            self.addCleanup(patch.stop)
        self.provider = K.KeychronLinkProvider()

    def test_m3_mini_is_reported_from_the_8c_collection_only(self):
        status, = self.provider.poll()
        self.assertEqual((status.key, status.name, status.level, status.charging, status.online,
                          status.source, status.kind),
                         ("keychron_link:d030", "Keychron M3 Mini", 99, False, True, "keychron_link", "mouse"))
        self.assertEqual(self.paths, [b"link-8c"])
        self.assertIn("reply: 51 06", " ".join(self.provider.diagnostics()))

    def test_unknown_mouse_is_named_by_its_product_id(self):
        reply = bytearray(CAPTURE)
        reply[6], reply[7] = 0x99, 0xD0
        self.reply = bytes(reply)
        self.assertEqual(self.provider.poll()[0].name, "Keychron mouse (d099)")

    def test_unusable_reply_gives_no_icon(self):
        self.reply = bytes.fromhex("52 61") + bytes(19)
        self.assertEqual(self.provider.poll(), [])
        self.assertIn("no device-info reply", " ".join(self.provider.diagnostics()))

    def test_io_error_gives_no_icon_and_is_logged(self):
        self.reply = OSError("HidD_SetFeature failed (87)")
        self.assertEqual(self.provider.poll(), [])
        self.assertIn("HidD_SetFeature failed", " ".join(self.provider.diagnostics()))

    def test_no_receiver_or_other_keychron_ids_are_not_opened(self):
        for entries in ([], [entry(product_id=0xD028)], [entry(usage_page=0xFF60, usage=0x61)]):
            with self.subTest(entries=entries):
                self.entries = entries
                self.assertEqual(self.provider.poll(), [])
        self.assertEqual(self.paths, [])

    def test_off_windows_nothing_is_sent(self):
        with mock.patch.object(K.sys, "platform", "linux"):
            self.assertIsNone(REAL_EXCHANGE(b"link-8c"))


class ExchangeTests(unittest.TestCase):
    """The Windows feature-report path, with hid.dll and kernel32 faked."""
    def run_exchange(self, replies, set_ok=True):
        sent, reads = [], []

        def set_feature(h, buf, n):
            sent.append(buf.raw[:n])
            return set_ok

        def get_feature(h, buf, n):
            reads.append(n)
            ctypes.memmove(buf, replies.pop(0), n)
            return True
        k32 = types.SimpleNamespace(CreateFileW=mock.Mock(return_value=1234), CloseHandle=mock.Mock(),
                                    GetLastError=lambda: 87)
        hid = types.SimpleNamespace(HidD_SetFeature=set_feature, HidD_GetFeature=get_feature)
        with mock.patch.object(K.ctypes, "windll", types.SimpleNamespace(kernel32=k32, hid=hid), create=True),              mock.patch.object(K.sys, "platform", "win32"), mock.patch.object(K.time, "sleep"):
            try:
                return REAL_EXCHANGE(b"link-8c"), sent, reads, k32
            except OSError as e:
                return e, sent, reads, k32

    def test_request_goes_out_at_21_bytes_and_reply_is_read(self):
        reply, sent, reads, k32 = self.run_exchange([CAPTURE])
        self.assertEqual(reply, CAPTURE)
        self.assertEqual(sent, [K.make_request()])
        self.assertEqual(reads, [K.REPORT_LEN])
        k32.CloseHandle.assert_called_once()

    def test_dropped_request_is_sent_again(self):
        reply, sent, reads, _ = self.run_exchange([STALE_07, CAPTURE])
        self.assertEqual(K.parse_info(reply), (99, False, 0xD036))
        self.assertEqual(sent, [K.make_request()] * 2)
        self.assertEqual(len(reads), 2)

    def test_attempts_stop_after_three_and_return_the_last_reply(self):
        reply, sent, reads, _ = self.run_exchange([STALE_07] * 3)
        self.assertEqual((len(sent), len(reads)), (K.ATTEMPTS, K.ATTEMPTS))
        self.assertIsNone(K.parse_info(reply))

    def test_refused_request_raises_and_closes(self):
        err, _, reads, k32 = self.run_exchange([CAPTURE], set_ok=False)
        self.assertIsInstance(err, OSError)
        self.assertIn("HidD_SetFeature failed (87)", str(err))
        self.assertEqual(reads, [])
        k32.CloseHandle.assert_called_once()


if __name__ == "__main__":
    unittest.main()
