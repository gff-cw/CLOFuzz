#!/usr/bin/env python3
"""Fixture coverage and structural-corruption checks for two bounded codecs."""
import ctypes
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
U8 = ctypes.c_ubyte
SZ = ctypes.c_size_t
PTR = ctypes.POINTER(U8)
TYPES = {"uint8": 0, "uint16": 1, "uint24": 2, "uint32": 3,
         "uint64": 4, "bytes": 5, "string": 6}


class CodecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="stateafl-codecs-")
        lib = Path(cls.temp.name) / "codecs.so"
        subprocess.run(["cc", "-std=c99", "-Wall", "-Wextra", "-Werror",
                        "-fPIC", "-shared", str(ROOT / "protocol_codec_modbus.c"),
                        str(ROOT / "protocol_codec_iec104.c"), "-o", str(lib)],
                       check=True)
        cls.lib = ctypes.CDLL(str(lib))
        cls.messages = {}
        for codec, directory in (("modbus", "modbus_tcp"),
                                 ("iec104", "iec60870_5_104")):
            cls.messages[codec] = json.loads(
                (ROOT / "protocols" / directory / "protocol_ir.json").read_text()
            )["messages"]
            for operation, args in {
                "validate": [PTR, SZ, ctypes.c_char_p, SZ],
                "repair": [PTR, SZ, ctypes.c_char_p, SZ],
                "field": [PTR, SZ, ctypes.c_char_p, ctypes.c_int, SZ,
                          ctypes.POINTER(SZ), ctypes.POINTER(SZ), ctypes.c_char_p, SZ],
                "frame": [PTR, SZ, ctypes.POINTER(SZ), ctypes.c_char_p, SZ],
                "replace": [PTR, ctypes.POINTER(SZ), SZ, ctypes.c_char_p,
                            ctypes.c_int, PTR, SZ, ctypes.c_char_p, SZ],
                "same_kind": [PTR, SZ, PTR, SZ],
            }.items():
                fun = getattr(cls.lib, f"pc_{codec}_{operation}")
                fun.argtypes = args
                fun.restype = ctypes.c_int

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def fn(self, codec, operation):
        return getattr(self.lib, f"pc_{codec}_{operation}")

    @staticmethod
    def buf(data):
        return (U8 * 260)(*data)

    def fixture(self, codec, name):
        return bytes.fromhex(next(m["example"] for m in self.messages[codec]
                                  if m["id"] == name))

    def test_all_complete_fixtures_and_exact_fields(self):
        for codec, messages in self.messages.items():
            for message in messages:
                if message["fixture_status"] != "complete":
                    continue
                with self.subTest(codec=codec, message=message["id"]):
                    wire = bytes.fromhex(message["example"])
                    buf, err = self.buf(wire), ctypes.create_string_buffer(256)
                    self.assertEqual(self.fn(codec, "validate")(buf, len(wire), err, 256),
                                     0, err.value)
                    self.assertEqual(self.fn(codec, "same_kind")(
                        buf, len(wire), buf, len(wire)), 1)
                    for field in message["fields"]:
                        off, size = SZ(), SZ()
                        self.assertEqual(self.fn(codec, "field")(
                            buf, len(wire), field["locator"].encode(),
                            TYPES[field["type"]], field["width"],
                            ctypes.byref(off), ctypes.byref(size), err, 256), 1, err.value)
                        expected_off = int(field["locator"].split(":")[1])
                        self.assertEqual(off.value, expected_off)
                        self.assertEqual(size.value, field["width"] or len(wire) - expected_off)

    def test_every_fragment_and_coalesced_frame(self):
        for codec, messages in self.messages.items():
            for message in messages:
                wire = bytes.fromhex(message["example"])
                buf = self.buf(wire + wire)
                size, err = SZ(), ctypes.create_string_buffer(256)
                with self.subTest(codec=codec, message=message["id"]):
                    for prefix in range(len(wire)):
                        self.assertEqual(self.fn(codec, "frame")(
                            buf, prefix, ctypes.byref(size), err, 256), 0, err.value)
                    self.assertEqual(self.fn(codec, "frame")(
                        buf, len(wire) * 2, ctypes.byref(size), err, 256), 1, err.value)
                    self.assertEqual(size.value, len(wire))

    def test_corrupt_inner_count_and_length_repair(self):
        for codec, name, changes in [
            ("modbus", "write_coils_partial", {4: 0xff, 12: 1}),
            ("modbus", "write_registers", {5: 0, 12: 99, 11: 8}),
            ("modbus", "read_response", {5: 0, 8: 7}),
            ("iec104", "interrogation", {1: 0, 7: 0x82, 4: 1}),
            ("iec104", "s_ack", {1: 0, 4: 3}),
        ]:
            with self.subTest(codec=codec, fixture=name):
                wire = self.fixture(codec, name)
                buf, err = self.buf(wire), ctypes.create_string_buffer(256)
                for offset, value in changes.items():
                    buf[offset] = value
                self.assertEqual(self.fn(codec, "validate")(buf, len(wire), err, 256), -1)
                self.assertEqual(self.fn(codec, "repair")(buf, len(wire), err, 256),
                                 0, err.value)
                self.assertEqual(self.fn(codec, "validate")(buf, len(wire), err, 256), 0)

    def test_coil_padding_and_sequence_bits(self):
        for codec, name, offset in [
            ("modbus", "write_coils_partial", 14),
            ("iec104", "interrogation", 2),
            ("iec104", "interrogation", 4),
            ("iec104", "s_ack", 4),
        ]:
            wire = self.fixture(codec, name)
            buf, err = self.buf(wire), ctypes.create_string_buffer(256)
            buf[offset] |= 0x80 if codec == "modbus" else 1
            self.assertEqual(self.fn(codec, "validate")(buf, len(wire), err, 256), -1)
            self.assertEqual(self.fn(codec, "repair")(buf, len(wire), err, 256), 0, err.value)

    def test_variable_data_replacement_repairs_counts(self):
        for name, locator, replacement, expected_quantity in [
            ("write_coils_partial", b"abs:13", b"\x01\x02\x03", 24),
            ("write_registers", b"abs:13", b"\x00\x01\x00\x02\x00\x03", 3),
            ("read_response", b"abs:9", b"\x00\x01\x00\x02", None),
            ("read_coils_response", b"abs:9", b"\x01\x02\x03", None),
        ]:
            with self.subTest(fixture=name):
                wire = self.fixture("modbus", name)
                buf, err, size = self.buf(wire), ctypes.create_string_buffer(256), SZ(len(wire))
                value = self.buf(replacement)
                self.assertEqual(self.fn("modbus", "replace")(
                    buf, ctypes.byref(size), 260, locator, TYPES["bytes"],
                    value, len(replacement), err, 256), 0, err.value)
                self.assertEqual(int.from_bytes(bytes(buf[4:6]), "big"), size.value - 6)
                start = int(locator.split(b":")[1])
                self.assertEqual(bytes(buf[start:size.value]), replacement)
                self.assertEqual(buf[start - 1], len(replacement))
                if expected_quantity is not None:
                    self.assertEqual(int.from_bytes(bytes(buf[10:12]), "big"), expected_quantity)

    def test_unsupported_replacement_and_invalid_data_are_atomic(self):
        for codec, fixture, locator, value in [
            ("modbus", "write_registers", b"abs:13", b"\x01"),
            ("modbus", "write_registers", b"abs:7", b"\x01\x02"),
            ("iec104", "interrogation", b"abs:6", b"\x64"),
        ]:
            wire = self.fixture(codec, fixture)
            buf, err, size = self.buf(wire), ctypes.create_string_buffer(256), SZ(len(wire))
            self.assertEqual(self.fn(codec, "replace")(
                buf, ctypes.byref(size), 260, locator, TYPES["bytes"],
                self.buf(value), len(value), err, 256), -1)
            self.assertTrue(err.value)
            self.assertEqual(bytes(buf[:len(wire)]), wire)
            self.assertEqual(size.value, len(wire))

    def test_same_kind_uses_services_not_sequences_or_session_values(self):
        wire = self.fixture("iec104", "interrogation_confirmation")
        changed = bytearray(wire)
        changed[2], changed[4], changed[9], changed[10], changed[15] = 2, 8, 3, 9, 25
        self.assertEqual(self.fn("iec104", "same_kind")(
            self.buf(changed), len(changed), self.buf(wire), len(wire)), 1)
        changed[8] |= 0x40
        self.assertEqual(self.fn("iec104", "same_kind")(
            self.buf(changed), len(changed), self.buf(wire), len(wire)), 0)


if __name__ == "__main__":
    unittest.main()
