#!/usr/bin/env python3
"""Focused wire-codec regression checks using independent Python readers."""
import ctypes
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from test_model_completeness import validate_enip, validate_ua_fixture

ROOT = Path(__file__).resolve().parents[2]
TYPES = dict(uint8=0, uint16=1, uint24=2, uint32=3, uint64=4,
             bytes=5, string=6, epath=9, nodeid=10)


class Codecs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        target = Path(cls.tmp.name) / 'codecs.so'
        subprocess.run(['cc', '-shared', '-fPIC', '-std=c99', '-Wall', '-Wextra', '-Werror',
                        '-I', str(ROOT), str(ROOT / 'protocol_codec_enip.c'),
                        str(ROOT / 'protocol_codec_opcua.c'), '-o', str(target)], check=True)
        cls.lib = ctypes.CDLL(str(target))
        cls.models = {}
        for codec, directory in [('enip', 'ethernet_ip_cip_tcp'), ('opcua', 'opcua_tcp')]:
            model = json.loads((ROOT / 'protocols' / directory / 'protocol_ir.json').read_text())
            cls.models[codec] = {m['id']: m for m in model['messages']}
            for function in ('validate', 'repair', 'field', 'replace', 'frame', 'same_kind'):
                getattr(cls.lib, f'pc_{codec}_{function}').restype = ctypes.c_int
            ptr, size, integer = ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int
            getattr(cls.lib, f'pc_{codec}_validate').argtypes = [ptr, size, ptr, size]
            getattr(cls.lib, f'pc_{codec}_repair').argtypes = [ptr, size, ptr, size]
            getattr(cls.lib, f'pc_{codec}_field').argtypes = [ptr, size, ctypes.c_char_p, integer, size, ptr, ptr, ptr, size]
            getattr(cls.lib, f'pc_{codec}_replace').argtypes = [ptr, ptr, size, ctypes.c_char_p, integer, ptr, size, ptr, size]
            getattr(cls.lib, f'pc_{codec}_frame').argtypes = [ptr, size, ptr, ptr, size]
            getattr(cls.lib, f'pc_{codec}_same_kind').argtypes = [ptr, size, ptr, size]

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def wire(self, codec, message):
        return bytes.fromhex(self.models[codec][message]['example'])

    def run_codec(self, codec, operation, data):
        wire = ctypes.create_string_buffer(data, max(4096, len(data) + 1))
        error = ctypes.create_string_buffer(256)
        status = getattr(self.lib, f'pc_{codec}_{operation}')(wire, len(data), error, 256)
        return status, wire.raw[:len(data)], error.value.decode()

    def field(self, codec, data, locator, kind, width=0):
        wire = ctypes.create_string_buffer(data)
        error = ctypes.create_string_buffer(256)
        off, size = ctypes.c_size_t(), ctypes.c_size_t()
        result = getattr(self.lib, f'pc_{codec}_field')(
            wire, len(data), locator.encode(), TYPES[kind], width,
            ctypes.byref(off), ctypes.byref(size), error, 256)
        self.assertEqual(result, 1, error.value)
        self.assertLessEqual(off.value + size.value, len(data))
        return off.value, size.value, data[off.value:off.value + size.value]

    def replace(self, codec, data, locator, kind, replacement, expected=0):
        wire = ctypes.create_string_buffer(data, len(data) + len(replacement) + 4096)
        value = ctypes.create_string_buffer(replacement)
        size = ctypes.c_size_t(len(data))
        error = ctypes.create_string_buffer(256)
        result = getattr(self.lib, f'pc_{codec}_replace')(
            wire, ctypes.byref(size), len(wire), locator.encode(), TYPES[kind],
            value, len(replacement), error, 256)
        self.assertEqual(result, expected, error.value)
        if expected:
            self.assertEqual(wire.raw[:len(data)], data, 'failed replacements must be atomic')
            self.assertEqual(size.value, len(data))
        return wire.raw[:size.value]

    def test_complete_fixture_validation_and_every_declared_field(self):
        for codec, models in self.models.items():
            for message, model in models.items():
                with self.subTest(codec=codec, message=message):
                    data = self.wire(codec, message)
                    self.assertEqual(self.run_codec(codec, 'validate', data)[0], 0)
                    if codec == 'enip':
                        validate_enip(message, data)
                    else:
                        validate_ua_fixture(data)
                    for field in model['fields']:
                        off, size, value = self.field(codec, data, field['locator'], field['type'], field['width'])
                        if field['width']:
                            self.assertEqual(size, field['width'])
                        if field['id'] == 'service_nodeid':
                            self.assertEqual(size, 4)
                            self.assertEqual(value, bytes.fromhex(field['default']))
                        if field['id'] in ('sender_certificate', 'receiver_thumbprint'):
                            self.assertEqual(size, 0)
                            self.assertEqual(data[off-4:off], b'\xff' * 4)

    def test_enip_repair_inner_counts_without_changing_payload(self):
        for message, offsets in [('send_rr', [2, 30, 34, 38, 41]),
                                 ('send_unit', [2, 30, 34, 42, 47]),
                                 ('send_rr_response', [2, 30, 34, 38, 43])]:
            original = self.wire('enip', message)
            damaged = bytearray(original)
            for at in offsets:
                damaged[at] ^= 0x7f
            self.assertEqual(self.run_codec('enip', 'validate', bytes(damaged))[0], -1)
            status, repaired, error = self.run_codec('enip', 'repair', bytes(damaged))
            self.assertEqual(status, 0, error)
            self.assertEqual(repaired, original)

    def test_enip_resize_epath_and_status_leaves(self):
        original = self.wire('enip', 'send_rr')
        wider_path = bytes.fromhex('210001002500010031000100')
        changed = self.replace('enip', original, 'abs:42', 'epath', wider_path)
        self.assertEqual(len(changed), len(original) + 6)
        self.assertEqual(changed[41], 6)
        self.assertEqual(int.from_bytes(changed[38:40], 'little'), 14)
        self.assertEqual(self.field('enip', changed, 'abs:42', 'epath')[2], wider_path)
        result = self.wire('enip', 'send_rr_response')
        changed = self.replace('enip', result, 'cip:additional_status', 'bytes', b'\x34\x12')
        self.assertEqual(changed[43], 1)
        self.assertEqual(self.field('enip', changed, 'cip:response_data', 'bytes')[2], b'\1\0')
        changed = self.replace('enip', changed, 'cip:additional_status', 'bytes', b'')
        self.assertEqual(changed, result)
        self.replace('enip', result, 'cip:response_data', 'bytes', b'\0' * 4, -1)
        self.replace('enip', original, 'abs:40', 'bytes', b'junk', -1)
        self.replace('enip', original, 'abs:42', 'epath', bytes.fromhex('200224013001'), -1)

    def test_ua_string_nodeid_and_nested_endpoint_resizing(self):
        for message, locator in [('hello', 'uabin:endpoint'), ('reverse_hello', 'uabin:server_uri'),
                                 ('error', 'uabin:reason'), ('message', 'uabin:endpoint'),
                                 ('message_response', 'uabin:endpoints[0].server.application_name.text')]:
            data = self.wire('opcua', message)
            value = 'opc.tcp://example.test:4840/\u03bb'.encode()
            changed = self.replace('opcua', data, locator, 'string', value)
            self.assertEqual(self.field('opcua', changed, locator, 'string')[2], value)
            validate_ua_fixture(changed)
        data = self.wire('opcua', 'message')
        changed = self.replace('opcua', data, 'abs:24', 'nodeid', b'\2\0\0' + struct.pack('<I', 428))
        self.assertEqual(len(changed), len(data) + 3)
        self.assertEqual(self.field('opcua', changed, 'abs:24', 'nodeid')[1], 7)
        self.assertEqual(self.field('opcua', changed, 'uabin:header.request_handle', 'uint32')[2], b'\2\0\0\0')
        validate_ua_fixture(changed)

    def test_ua_repair_rejects_ambiguous_inner_corruption_and_security(self):
        data = self.wire('opcua', 'open_channel')
        damaged = bytearray(data);damaged[4] ^= 0x55
        self.assertEqual(self.run_codec('opcua', 'repair', bytes(damaged))[:2], (0, data))
        damaged = bytearray(data);damaged[12] ^= 0x55
        self.assertEqual(self.run_codec('opcua', 'repair', bytes(damaged))[0], -1)
        self.replace('opcua', data, 'uabin:policy_uri', 'string', b'urn:unsupported', -1)
        self.replace('opcua', data, 'uabin:sender_certificate', 'bytes', b'cert', -1)
        self.replace('opcua', data, 'uabin:sender_certificate', 'bytes', b'')
        self.replace('opcua', data, 'uabin:open.security_mode', 'uint32', struct.pack('<I', 2), -1)
        self.replace('opcua', data, 'abs:8', 'bytes', b'opaque body', -1)

    def test_fragment_coalescing_and_semantic_kind(self):
        for codec, message in [('enip', 'send_unit'), ('opcua', 'message')]:
            data = self.wire(codec, message)
            frame = getattr(self.lib, f'pc_{codec}_frame')
            for prefix in range(len(data)):
                size = ctypes.c_size_t();error = ctypes.create_string_buffer(256)
                self.assertEqual(frame(ctypes.create_string_buffer(data[:prefix]), prefix,
                                       ctypes.byref(size), error, 256), 0)
            size = ctypes.c_size_t();error = ctypes.create_string_buffer(256)
            self.assertEqual(frame(ctypes.create_string_buffer(data + data), len(data) * 2,
                                   ctypes.byref(size), error, 256), 1)
            self.assertEqual(size.value, len(data))
        message = self.wire('opcua', 'message')
        fault = self.wire('opcua', 'service_fault')
        self.assertEqual(self.lib.pc_opcua_same_kind(ctypes.create_string_buffer(message), len(message),
                                                  ctypes.create_string_buffer(fault), len(fault)), 0)


if __name__ == '__main__':
    unittest.main()
