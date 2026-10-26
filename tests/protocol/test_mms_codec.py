#!/usr/bin/env python3
"""Focused checks of the bounded MMS wire codec against captured full records."""
import ctypes as C
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
TYPES = {name: n for n, name in enumerate((
    'uint8', 'uint16', 'uint24', 'uint32', 'uint64', 'bytes', 'string',
    'bacnet_tags', 'ber_tlv', 'epath', 'nodeid'))}


class MMSCodec(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='stateafl-mms-codec-')
        library = Path(cls.directory.name) / 'codec.so'
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra',
                        '-Werror', '-fPIC', '-shared', 'protocol_codec_mms.c',
                        '-o', str(library)], cwd=ROOT, check=True)
        cls.lib = C.CDLL(str(library))
        cls.lib.pc_mms_validate.argtypes = [C.c_void_p, C.c_size_t, C.c_void_p, C.c_size_t]
        cls.lib.pc_mms_repair.argtypes = list(cls.lib.pc_mms_validate.argtypes)
        cls.lib.pc_mms_field.argtypes = [C.c_void_p, C.c_size_t, C.c_char_p, C.c_int,
                                        C.c_size_t, C.POINTER(C.c_size_t),
                                        C.POINTER(C.c_size_t), C.c_void_p, C.c_size_t]
        cls.lib.pc_mms_replace.argtypes = [C.c_void_p, C.POINTER(C.c_size_t), C.c_size_t,
                                          C.c_char_p, C.c_int, C.c_void_p, C.c_size_t,
                                          C.c_void_p, C.c_size_t]
        cls.lib.pc_mms_frame.argtypes = [C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t),
                                        C.c_void_p, C.c_size_t]
        cls.lib.pc_mms_same_kind.argtypes = [C.c_void_p, C.c_size_t, C.c_void_p, C.c_size_t]
        cls.model = json.loads((ROOT / 'protocols/iec61850_mms_tcp/protocol_ir.json').read_text())
        cls.messages = {m['id']: m for m in cls.model['messages']}
        cls.fixtures = {m['id']: bytes.fromhex(m['example']) for m in cls.model['messages']}

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def validate(self, raw):
        error = C.create_string_buffer(256)
        result = self.lib.pc_mms_validate(C.create_string_buffer(bytes(raw)), len(raw), error, len(error))
        return result, error.value.decode()

    def locator_kind(self, locator):
        if locator == 'ber:presentation':
            return 'ber_tlv'
        if locator == 'ber:mms.invoke':
            return 'uint32'
        if locator in ('ber:mms.domain', 'ber:mms.item', 'ber:mms.data'):
            return 'string'
        return 'bytes'

    def field(self, raw, locator, kind=None, width=0):
        kind = kind or self.locator_kind(locator)
        offset, length = C.c_size_t(), C.c_size_t()
        error = C.create_string_buffer(256)
        result = self.lib.pc_mms_field(C.create_string_buffer(bytes(raw)), len(raw),
                                       locator.encode(), TYPES[kind], width,
                                       C.byref(offset), C.byref(length), error, len(error))
        return result, offset.value, length.value

    def replace(self, raw, locator, value, capacity=65535):
        buffer = C.create_string_buffer(capacity)
        buffer[:len(raw)] = raw
        size = C.c_size_t(len(raw))
        error = C.create_string_buffer(256)
        result = self.lib.pc_mms_replace(buffer, C.byref(size), capacity, locator.encode(),
                                         TYPES[self.locator_kind(locator)], C.create_string_buffer(value), len(value),
                                         error, len(error))
        return result, bytes(buffer[:size.value]), error.value.decode()

    def test_all_fourteen_fixtures_and_all_declared_locators(self):
        self.assertEqual(len(self.fixtures), 14)
        for mid, raw in self.fixtures.items():
            with self.subTest(message=mid):
                self.assertEqual(self.validate(raw), (0, ''))
                for f in self.messages[mid]['fields']:
                    status, at, length = self.field(raw, f['locator'], f['type'], f['width'])
                    self.assertEqual(status, 1, f)
                    self.assertLessEqual(at + length, len(raw))
                    actual = raw[at:at + length]
                    if f['type'].startswith('uint'):
                        expected = f['default']
                        if f['id'] == 'tpkt_length':
                            expected = len(raw)
                        elif f['id'] == 'cotp_li' and mid.startswith('cotp_'):
                            expected = len(raw) - 5
                        self.assertEqual(int.from_bytes(actual, 'big'), expected, f)
                    elif f['type'] == 'string':
                        self.assertEqual(actual.decode(), f['default'], f)
                    else:
                        self.assertEqual(actual.hex(), f['default'], f)
        self.assertEqual(self.field(self.fixtures['conclude'], 'ber:mms.invoke')[0], 0)
        self.assertEqual(self.field(self.fixtures['cotp_cr'], 'iso:session')[0], 0)

    def test_every_message_family_is_distinct(self):
        for left, a in self.fixtures.items():
            for right, b in self.fixtures.items():
                self.assertEqual(self.lib.pc_mms_same_kind(a, len(a), b, len(b)), left == right,
                                 (left, right))

    def test_string_resize_across_ber_length_thresholds(self):
        for mid, locator in [('read', 'ber:mms.domain'), ('read', 'ber:mms.item'),
                             ('write', 'ber:mms.domain'), ('write', 'ber:mms.item'),
                             ('write', 'ber:mms.data')]:
            for length in [1, 17, 127, 128, 255, 256, 4096]:
                with self.subTest(message=mid, locator=locator, length=length):
                    status, raw, error = self.replace(self.fixtures[mid], locator, b'x' * length)
                    self.assertEqual(status, 0, error)
                    self.assertEqual(self.validate(raw), (0, ''))
                    present, at, count = self.field(raw, locator)
                    self.assertEqual((present, count, raw[at:at + count]), (1, length, b'x' * length))
                    original = self.fixtures[mid]
                    self.assertEqual(self.lib.pc_mms_same_kind(raw, len(raw), original, len(original)), 1)
        status, raw, error = self.replace(self.fixtures['write'], 'ber:mms.data', b'')
        self.assertEqual(status, 0, error)
        self.assertEqual(self.field(raw, 'ber:mms.data')[2], 0)

    def test_dynamic_integer_content_width(self):
        raw = self.fixtures['read']
        for value in [1, 127, 128, 255, 256, 65535, 65536, 2**31, 2**32 - 1]:
            content = value.to_bytes(max(1, (value.bit_length() + 7) // 8), 'big')
            if content[0] & 128:
                content = b'\0' + content
            status, replaced, error = self.replace(raw, 'ber:mms.invoke', content)
            self.assertEqual(status, 0, error)
            present, at, count = self.field(replaced, 'ber:mms.invoke', 'uint32', 4)
            self.assertEqual((present, count), (1, len(content)))
            self.assertEqual(int.from_bytes(replaced[at:at + count], 'big'), value)
        for content in [b'', b'\x80', b'\x01' * 5, b'\0' * 6]:
            self.assertEqual(self.replace(raw, 'ber:mms.invoke', content)[0], -1)

    def test_reject_opaque_and_invalid_leaf_replacements_transactionally(self):
        raw = self.fixtures['write']
        for locator, value in [('ber:presentation', b'garbage'), ('iso:session', b'garbage'),
                               ('abs:11', b'garbage'), ('ber:mms.domain', b''),
                               ('ber:mms.item', b'\xff'), ('ber:mms.data', b'\0')]:
            status, after, error = self.replace(raw, locator, value)
            self.assertEqual(status, -1, (locator, error))
            self.assertEqual(after, raw)
        status, after, _ = self.replace(raw, 'ber:mms.data', b'x' * 100, capacity=len(raw))
        self.assertEqual((status, after), (-1, raw))

    def test_length_corruptions_and_repair(self):
        for mid, original in self.fixtures.items():
            raw = bytearray(original); raw[3] ^= 1
            self.assertEqual(self.validate(raw)[0], -1)
            error = C.create_string_buffer(256)
            buffer = C.create_string_buffer(bytes(raw))
            self.assertEqual(self.lib.pc_mms_repair(buffer, len(raw), error, len(error)), 0, error.value)
            self.assertEqual(bytes(buffer[:len(raw)]), original)
            if mid not in ('cotp_cr', 'cotp_cc'):
                _, at, _ = self.field(original, 'ber:presentation')
                raw = bytearray(original); raw[at + 1] = 0x80  # Indefinite BER is outside profile.
                self.assertEqual(self.validate(raw)[0], -1)
        # A changed inner BER length cannot be inferred safely from a broken tree.
        raw = bytearray(self.fixtures['read']); raw[12] = 0x7f
        self.assertEqual(self.validate(raw)[0], -1)
        raw = bytearray(self.fixtures['read']); raw[14] ^= 1
        self.assertEqual(self.validate(raw)[0], -1)
        for mid in ['associate', 'associate_response', 'release', 'release_response']:
            original = self.fixtures[mid]
            _, presentation, _ = self.field(original, 'ber:presentation')
            root_last_length = presentation + 1
            if original[root_last_length] & 128:
                root_last_length += original[root_last_length] & 127
            for at in [8, presentation - 1, root_last_length]:
                raw = bytearray(original); raw[at] ^= 1
                self.assertEqual(self.validate(raw)[0], -1)
                buffer = C.create_string_buffer(bytes(raw)); error = C.create_string_buffer(256)
                self.assertEqual(self.lib.pc_mms_repair(buffer, len(raw), error, len(error)), 0,
                                 (mid, at, error.value))
                self.assertEqual(bytes(buffer[:len(raw)]), original)

    def test_fragmented_and_coalesced_frames(self):
        for raw in self.fixtures.values():
            for cut in range(len(raw)):
                length = C.c_size_t(999)
                self.assertEqual(self.lib.pc_mms_frame(raw, cut, C.byref(length), None, 0), 0)
                self.assertEqual(length.value, 0)
            joined = raw + self.fixtures['read_response']
            length = C.c_size_t()
            self.assertEqual(self.lib.pc_mms_frame(joined, len(joined), C.byref(length), None, 0), 1)
            self.assertEqual(length.value, len(raw))
        for raw in [b'\x04', b'\x03\x01', b'\x03\0\0\x03']:
            length = C.c_size_t()
            self.assertEqual(self.lib.pc_mms_frame(raw, len(raw), C.byref(length), None, 0), -1)

    def test_malformed_random_input_is_bounded(self):
        rng = random.Random(0x61850)
        for _ in range(10000):
            if rng.randrange(2):
                raw = bytearray(rng.choice(list(self.fixtures.values())))
                for _ in range(rng.randrange(1, 9)):
                    raw[rng.randrange(len(raw))] = rng.randrange(256)
            else:
                raw = rng.randbytes(rng.randrange(256))
            result, error = self.validate(raw)
            self.assertIn(result, (0, -1))
            if result:
                self.assertTrue(error)

    @unittest.skipUnless(shutil.which('clang'), 'clang is needed for ASan/UBSan')
    def test_standalone_sanitizer_stress(self):
        binary = Path(self.directory.name) / 'mms-sanitizers'
        subprocess.run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-g',
                        '-I.', 'protocol_codec_mms.c',
                        'tests/protocol/test_mms_codec_sanitizers.c', '-o', str(binary)],
                       cwd=ROOT, check=True)
        env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',
                   UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
        subprocess.run([str(binary), *(raw.hex() for raw in self.fixtures.values())],
                       cwd=ROOT, env=env, check=True, timeout=60)


if __name__ == '__main__':
    unittest.main()
