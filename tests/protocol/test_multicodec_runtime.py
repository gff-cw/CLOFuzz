#!/usr/bin/env python3
"""Exercise compiled runtime IR through the real C runtime and all wire codecs.

The independent Python readers check successful mutation output. Session tests
feed fragmented/coalesced responses directly through the same runtime API used
by the fuzzer; no server, socket, or response-binding mock is involved.
"""
import ctypes
import copy
from contextlib import contextmanager
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from test_model_completeness import VALIDATORS, validate_ua_fixture

ROOT = Path(__file__).resolve().parents[2]
PROFILES = {
    'bacnet': ('bacnet_ip', ['who_is', 'read_property']),
    'modbus': ('modbus_tcp', ['read_holding', 'write_registers', 'write_coils_partial']),
    'iec104': ('iec60870_5_104', ['start_act', 'test_act', 's_ack', 'interrogation']),
    'mms': ('iec61850_mms_tcp', ['cotp_cr', 'associate', 'get_name_list', 'read', 'write']),
    'enip': ('ethernet_ip_cip_tcp', ['register', 'send_rr', 'send_rr']),
    'opcua': ('opcua_tcp', ['hello', 'open_channel', 'message']),
}
TYPES = dict(uint8=0, uint16=1, uint24=2, uint32=3, uint64=4,
             bytes=5, string=6, bacnet_tags=7, ber_tlv=8, epath=9, nodeid=10)
RNG = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_uint32)


def pack_records(wires):
    return b''.join(struct.pack('<I', len(wire)) + wire for wire in wires)


def unpack_records(data):
    wires = []
    at = 0
    while at < len(data):
        if at + 4 > len(data):
            raise AssertionError('truncated record prefix')
        size, = struct.unpack_from('<I', data, at)
        at += 4
        if not size or at + size > len(data):
            raise AssertionError('invalid record size')
        wires.append(data[at:at + size])
        at += size
    return wires


def deterministic(seed):
    state = seed or 1

    @RNG
    def draw(limit):
        nonlocal state
        state ^= (state << 13) & 0xffffffff
        state ^= state >> 17
        state ^= (state << 5) & 0xffffffff
        state &= 0xffffffff
        return state % limit if limit else 0
    return draw


def scripted(values):
    values = iter(values)

    @RNG
    def draw(limit):
        value = next(values, 0)
        return value % limit if limit else 0
    return draw


class Runtime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='stateafl-multicodec-')
        cls.directory = Path(cls.tmp.name)
        binary = cls.directory / 'runtime.so'
        sources = ['protocol_runtime.c'] + [f'protocol_codec_{codec}.c'
                  for codec in ('modbus', 'iec104', 'mms', 'enip', 'opcua')]
        subprocess.run([os.environ.get('CC', 'clang'), '-shared', '-fPIC', '-std=gnu11',
                        '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter', '-I.',
                        *sources, '-o', str(binary)], cwd=ROOT, check=True)
        cls.lib = ctypes.CDLL(str(binary))
        ptr, size, integer = ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int
        cls.lib.proto_load.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ptr, size]
        cls.lib.proto_load.restype = ptr
        cls.lib.proto_free.argtypes = [ptr]
        cls.lib.proto_session_begin.argtypes = [ptr]
        cls.lib.proto_before_send.argtypes = [ptr, ptr, size, ptr, size]
        cls.lib.proto_before_send.restype = integer
        cls.lib.proto_after_response.argtypes = [ptr, ptr, size]
        cls.lib.proto_set_prefix.argtypes = [ptr, ptr, size, ptr, size]
        cls.lib.proto_set_prefix.restype = integer
        cls.lib.proto_mutate.argtypes = [ptr, ptr, size, ptr, size, integer, integer,
                                         RNG, ptr, ptr, ptr, size]
        cls.lib.proto_mutate.restype = integer
        cls.lib.proto_write_stats.argtypes = [ptr, ctypes.c_char_p]
        cls.lib.proto_records_validate.argtypes = [ptr, size, ptr, ptr, size]
        cls.lib.proto_records_validate.restype = integer
        cls.lib.proto_bacnet_field.argtypes = [ptr, size, ctypes.c_char_p, ptr, ptr, ptr, size]
        cls.lib.proto_bacnet_field.restype = integer
        for codec in ('modbus', 'iec104', 'mms', 'enip', 'opcua'):
            getattr(cls.lib, f'pc_{codec}_validate').argtypes = [ptr, size, ptr, size]
            getattr(cls.lib, f'pc_{codec}_validate').restype = integer
            getattr(cls.lib, f'pc_{codec}_field').argtypes = [ptr, size, ctypes.c_char_p,
                                                          integer, size, ptr, ptr, ptr, size]
            getattr(cls.lib, f'pc_{codec}_field').restype = integer
            getattr(cls.lib, f'pc_{codec}_same_kind').argtypes = [ptr, size, ptr, size]
            getattr(cls.lib, f'pc_{codec}_same_kind').restype = integer
        cls.models = {}
        cls.states = {}
        for codec, (profile, _) in PROFILES.items():
            cls.models[codec] = json.loads((ROOT / 'protocols' / profile / 'protocol_ir.json').read_text())
            cls.states[codec] = json.loads((ROOT / 'protocols' / profile / 'state_ir.json').read_text())

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def messages(self, codec):
        return {m['id']: m for m in self.models[codec]['messages']}

    def wire(self, codec, message):
        return bytes.fromhex(self.messages(codec)[message]['example'])

    @contextmanager
    def engine(self, codec, protocol=None, state=None):
        error = ctypes.create_string_buffer(1024)
        if protocol is None:
            directory = ROOT / 'protocols' / PROFILES[codec][0]
            protocol, state = directory / 'protocol_ir.json', directory / 'state_ir.json'
        engine = self.lib.proto_load(os.fsencode(protocol), os.fsencode(state), error, len(error))
        self.assertTrue(engine, f'{codec} load: {error.value.decode()}')
        try:
            yield engine
        finally:
            self.lib.proto_free(engine)

    def before(self, engine, data, expected=0):
        wire = ctypes.create_string_buffer(data)
        error = ctypes.create_string_buffer(1024)
        result = self.lib.proto_before_send(engine, wire, len(data), error, len(error))
        self.assertEqual(result, expected, error.value.decode())
        return wire.raw[:len(data)]

    def after(self, engine, data):
        self.lib.proto_after_response(engine, ctypes.create_string_buffer(data), len(data))

    def prefix(self, engine, wires, expected=0):
        data = pack_records(wires)
        error = ctypes.create_string_buffer(1024)
        result = self.lib.proto_set_prefix(engine, ctypes.create_string_buffer(data), len(data), error, len(error))
        self.assertEqual(result, expected, error.value.decode())

    def mutate(self, engine, wires, candidate, layer, rng, mode=0):
        data = pack_records(wires)
        output, length = ctypes.c_void_p(), ctypes.c_size_t()
        error = ctypes.create_string_buffer(1024)
        result = self.lib.proto_mutate(engine, ctypes.create_string_buffer(data), len(data),
                                      ctypes.create_string_buffer(candidate), len(candidate), mode, layer,
                                      rng, ctypes.byref(output), ctypes.byref(length), error, len(error))
        if result:
            self.assertEqual(result, -1)
            self.assertFalse(output.value)
            self.assertEqual(length.value, 0)
            self.assertTrue(error.value)
            return result, b'', error.value.decode()
        self.assertTrue(output.value)
        data = ctypes.string_at(output, length.value)
        count = ctypes.c_size_t()
        self.assertEqual(self.lib.proto_records_validate(ctypes.create_string_buffer(data), len(data),
                                                        ctypes.byref(count), error, len(error)), 0)
        self.assertEqual(count.value, len(unpack_records(data)))
        return 0, data, ''

    def field(self, codec, data, locator, kind, width=0):
        data = bytes(data)
        off, length = ctypes.c_size_t(), ctypes.c_size_t()
        error = ctypes.create_string_buffer(1024)
        if codec == 'bacnet':
            result = self.lib.proto_bacnet_field(ctypes.create_string_buffer(data), len(data),
                                                locator.encode(), ctypes.byref(off), ctypes.byref(length), error, len(error))
        else:
            result = getattr(self.lib, f'pc_{codec}_field')(
                ctypes.create_string_buffer(data), len(data), locator.encode(), TYPES[kind], width,
                ctypes.byref(off), ctypes.byref(length), error, len(error))
        self.assertEqual(result, 1, error.value.decode())
        return off.value, length.value

    def set_field(self, codec, data, locator, kind, value):
        data = bytearray(data)
        off, length = self.field(codec, data, locator, kind)
        self.assertEqual(length, len(value))
        data[off:off + length] = value
        return bytes(data)

    def set_fields(self, codec, data, values):
        updates = []
        for locator, kind, value in values:
            offset, width = self.field(codec, data, locator, kind)
            self.assertEqual(width, len(value))
            updates.append((offset, value))
        result = bytearray(data)
        for offset, value in updates:
            result[offset:offset + len(value)] = value
        return bytes(result)

    def identify(self, codec, data):
        if codec != 'bacnet':
            error = ctypes.create_string_buffer(1024)
            self.assertEqual(getattr(self.lib, f'pc_{codec}_validate')(
                ctypes.create_string_buffer(data), len(data), error, len(error)), 0, error.value.decode())
        for message, model in self.messages(codec).items():
            if model['direction'] != 'request':
                continue
            if codec != 'bacnet':
                example = bytes.fromhex(model['example'])
                if not getattr(self.lib, f'pc_{codec}_same_kind')(
                        ctypes.create_string_buffer(data), len(data), ctypes.create_string_buffer(example), len(example)):
                    continue
            try:
                VALIDATORS[codec](message, data)
                return message
            except (ValueError, IndexError, struct.error, UnicodeError):
                pass
        self.fail(f'{codec}: successful mutation has no independently valid request: {data.hex()}')

    def validate_sequence(self, codec, records, initial=None):
        state = initial or self.states[codec]['initial']
        graph = self.states[codec]['transitions']
        for data in unpack_records(records):
            message = self.identify(codec, data)
            transitions = [t for t in graph if t['from'] == state and t['message'] == message]
            self.assertEqual(len(transitions), 1, (codec, state, message))
            transition = transitions[0]
            state = transition['to']
            if transition.get('response'):
                response = [t for t in graph if t['from'] == state and t['message'] == transition['response']]
                self.assertEqual(len(response), 1)
                state = response[0]['to']
        return state

    def stats(self, engine):
        target = self.directory / 'stats.json'
        self.lib.proto_write_stats(engine, os.fsencode(target))
        return json.loads(target.read_text())

    def test_all_six_models_and_mutation_layers_across_varied_draws(self):
        for codec, (_, names) in PROFILES.items():
            wires = [self.wire(codec, name) for name in names]
            candidate = b''.join(wires)
            with self.subTest(codec=codec), self.engine(codec) as engine:
                self.assertTrue(self.models[codec]['support']['runtime'])
                self.validate_sequence(codec, pack_records(wires))
                for layer in (1, 2, 4):
                    successes = set()
                    for seed in range(1, 97):
                        result, data, _ = self.mutate(engine, wires, candidate, layer,
                                                      deterministic(0x51a70000 + seed))
                        if not result:
                            self.validate_sequence(codec, data)
                            successes.add(data)
                    self.assertTrue(successes, f'{codec} layer {layer} had no successful deterministic draw')
                    if layer in (1, 4):
                        self.assertGreater(len(successes), 1, f'{codec} layer {layer} did not vary')

    def test_message_names_do_not_select_wire_codecs_or_session_behavior(self):
        for codec, (_, names) in PROFILES.items():
            protocol, state = copy.deepcopy(self.models[codec]), copy.deepcopy(self.states[codec])
            renamed = {message['id']: f'author_message_{index}'
                       for index, message in enumerate(protocol['messages'])}
            for message in protocol['messages']:
                message['id'] = renamed[message['id']]
                for dependency in message['dependencies']:
                    if dependency.get('message'):
                        dependency['message'] = renamed[dependency['message']]
            for transition in state['transitions']:
                transition['message'] = renamed[transition['message']]
                if transition.get('response'):
                    transition['response'] = renamed[transition['response']]
            pp, sp = self.directory / f'{codec}-protocol.json', self.directory / f'{codec}-state.json'
            pp.write_text(json.dumps(protocol));sp.write_text(json.dumps(state))
            wires = [self.wire(codec, message) for message in names]
            with self.subTest(codec=codec), self.engine(codec) as original, self.engine(codec, pp, sp) as custom:
                for layer in (1, 2, 4):
                    for seed in range(1, 49):
                        expected = self.mutate(original, wires, b''.join(wires), layer, deterministic(seed))
                        actual = self.mutate(custom, wires, b''.join(wires), layer, deterministic(seed))
                        self.assertEqual(actual[:2], expected[:2])
                        if expected[0] == 0:
                            break
                    else:
                        self.fail(f'{codec} layer {layer}: no successful renamed-model draw')

    def test_mms_scalar_head_enums_reencode_positive_ber_integers(self):
        protocol = copy.deepcopy(self.models['mms'])
        cases = [('associate', 'max_outstanding_calling', ['cotp_cr']),
                 ('read', 'invoke_id', ['cotp_cr', 'associate'])]
        for message_name, field_name, _ in cases:
            message = next(message for message in protocol['messages'] if message['id'] == message_name)
            field = next(field for field in message['fields'] if field['id'] == field_name)
            field.update(values=[256, 65535], strategies=['enum'])
        pp, sp = self.directory / 'mms-head-enums.json', self.directory / 'mms-head-state.json'
        pp.write_text(json.dumps(protocol));sp.write_text(json.dumps(self.states['mms']))
        with self.engine('mms', pp, sp) as engine:
            for message_name, field_name, prefix in cases:
                self.prefix(engine, [self.wire('mms', name) for name in prefix])
                model = next(message for message in protocol['messages'] if message['id'] == message_name)
                choices = [field for field in model['fields']
                           if field['role'] == 'head' and field['mutability'] in ('fuzzable', 'conditional')]
                field = next(field for field in choices if field['id'] == field_name)
                original = self.wire('mms', message_name)
                for enum_index, value in enumerate((256, 65535)):
                    with self.subTest(message=message_name, field=field_name, value=value):
                        result, records, error = self.mutate(engine, [original], original, 1,
                                                            scripted([0, choices.index(field), 0, enum_index]))
                        self.assertEqual(result, 0, error)
                        changed, = unpack_records(records)
                        offset, width = self.field('mms', changed, field['locator'], field['type'], field['width'])
                        encoded = value.to_bytes((value.bit_length() + 7) // 8, 'big')
                        if encoded[0] & 0x80:
                            encoded = b'\0' + encoded
                        self.assertEqual(changed[offset:offset + width], encoded)
                        self.assertEqual(int.from_bytes(changed[offset:offset + width], 'big'), value)
                        self.assertEqual(int.from_bytes(changed[2:4], 'big'), len(changed))
                        self.assertGreater(len(changed), len(original))
                        VALIDATORS['mms'](message_name, changed)

    def test_alias_specific_response_binding_resolves_or_is_rejected_at_load(self):
        protocol = copy.deepcopy(self.models['modbus'])
        message = next(message for message in protocol['messages'] if message['id'] == 'read_holding')
        next(field for field in message['fields'] if field['id'] == 'transaction')['mutability'] = 'runtime_bound'
        message['dependencies'].append(dict(op='bind_from_response', target='transaction', source='transaction',
                                            message='write_coils_partial_response', scope='connection'))
        pp, sp = self.directory / 'alias-binding-protocol.json', self.directory / 'alias-binding-state.json'
        pp.write_text(json.dumps(protocol));sp.write_text(json.dumps(self.states['modbus']))
        error = ctypes.create_string_buffer(1024)
        engine = self.lib.proto_load(os.fsencode(pp), os.fsencode(sp), error, len(error))
        if not engine:
            reason = error.value.decode().lower()
            self.assertTrue(any(word in reason for word in ('alias', 'ambig', 'overlap')), reason)
            return
        try:
            self.before(engine, self.wire('modbus', 'read_holding'), -1)
            request = bytearray(self.wire('modbus', 'write_coils_partial'))
            request[:2] = bytes.fromhex('abcd')
            self.before(engine, bytes(request))
            response = bytearray(self.wire('modbus', 'write_coils_partial_response'))
            response[:2] = request[:2]
            self.after(engine, bytes(response))
            self.assertEqual(self.stats(engine)['correlated_responses'], 1)
            bound = self.before(engine, self.wire('modbus', 'read_holding'))
            self.assertEqual(bound[:2], request[:2])
        finally:
            self.lib.proto_free(engine)

    def test_near_valid_breaks_one_framing_length_and_before_send_preserves_it(self):
        lengths = {'bacnet': (2, 2, 'big'), 'modbus': (4, 2, 'big'),
                   'iec104': (1, 1, 'little'), 'mms': (2, 2, 'big'),
                   'enip': (2, 2, 'little'), 'opcua': (4, 4, 'little')}
        for codec, (_, names) in PROFILES.items():
            wires = [self.wire(codec, name) for name in names]
            candidate = b''.join(wires)
            with self.subTest(codec=codec), self.engine(codec) as engine:
                for seed in range(1, 49):
                    status, valid, _ = self.mutate(engine, wires, candidate, 1, deterministic(seed))
                    if status == 0:
                        break
                else:
                    self.fail(f'{codec}: no valid HEAD draw for near-valid comparison')
                status, broken, error = self.mutate(engine, wires, candidate, 1, deterministic(seed), mode=1)
                self.assertEqual(status, 0, error)
                valid_wires, broken_wires = unpack_records(valid), unpack_records(broken)
                self.assertEqual(len(valid_wires), len(broken_wires))
                changes = [(before, after) for before, after in zip(valid_wires, broken_wires) if before != after]
                self.assertEqual(len(changes), 1)
                before, after = changes[0]
                off, width, endian = lengths[codec]
                self.assertEqual(before[:off], after[:off])
                self.assertEqual(before[off + width:], after[off + width:])
                self.assertEqual(int.from_bytes(after[off:off + width], endian),
                                 int.from_bytes(before[off:off + width], endian) + 1)
                self.assertEqual(self.before(engine, after, -1), after)

    def test_content_projection_uses_original_wire_offsets_and_repairs_lengths(self):
        cases = [
            ('bacnet', [], 'read_property', 'object_id', bytes.fromhex('0200002a')),
            ('modbus', [], 'write_registers', 'data', bytes.fromhex('12345678')),
            ('iec104', ['start_act'], 'interrogation', 'qoi', b'\x24'),
            ('mms', ['cotp_cr', 'associate'], 'write', 'value', b'reproducible runtime value'),
            ('enip', ['register'], 'send_rr', 'epath', bytes.fromhex('210001002500010031000100')),
            ('opcua', ['hello', 'open_channel'], 'message', 'endpoint', b'opc.tcp://integration.example:4840/longer'),
        ]
        for codec, prefix, message, field_name, value in cases:
            with self.subTest(codec=codec), self.engine(codec) as engine:
                self.prefix(engine, [self.wire(codec, name) for name in prefix])
                wire = self.wire(codec, message)
                fields = self.messages(codec)[message]['fields']
                choices = [f for f in fields if f['role'] == 'content' and f['mutability'] in ('fuzzable', 'conditional')
                           and f['id'] != 'array_index']
                field = next(f for f in choices if f['id'] == field_name)
                offset, width = self.field(codec, wire, field['locator'], field['type'], field['width'])
                projected = bytes(byte - 32 for byte in value) if field['type'] == 'string' else value
                candidate = wire[:offset] + projected + wire[offset + width:]
                result, data, error = self.mutate(engine, [wire], candidate, 2,
                                                  scripted([0, choices.index(field), 0, len(value) - field['min']]))
                self.assertEqual(result, 0, error)
                changed, = unpack_records(data)
                off, size = self.field(codec, changed, field['locator'], field['type'], field['width'])
                self.assertEqual(changed[off:off + size], value)
                if codec == 'enip':
                    self.assertEqual(changed[41], len(value) // 2)
                    self.assertEqual(int.from_bytes(changed[2:4], 'little'), len(changed) - 24)
                elif codec == 'opcua':
                    self.assertEqual(struct.unpack_from('<I', changed, 4)[0], len(changed))
                    validate_ua_fixture(changed)
                elif codec == 'modbus':
                    self.assertEqual(changed[12], len(value))
                    self.assertEqual(int.from_bytes(changed[10:12], 'big'), len(value) // 2)
                elif codec == 'mms':
                    VALIDATORS[codec](message, changed)

    def test_scalar_content_projection_skips_replay_prefixes_and_preceding_wires(self):
        cases = [('bacnet', 'who_is', 'read_property', 'object_id', bytes.fromhex('0200002a')),
                 ('modbus', 'read_holding', 'write_registers', 'address', bytes.fromhex('1234')),
                 ('iec104', 'start_act', 'interrogation', 'common_address', bytes.fromhex('3412'))]
        for codec, first, selected, field_name, value in cases:
            with self.subTest(codec=codec), self.engine(codec) as engine:
                wires = [self.wire(codec, first), self.wire(codec, selected)]
                fields = [field for field in self.messages(codec)[selected]['fields']
                          if field['role'] == 'content' and field['mutability'] in ('fuzzable', 'conditional')
                          and field['id'] != 'array_index']
                field = next(field for field in fields if field['id'] == field_name)
                off, width = self.field(codec, wires[1], field['locator'], field['type'], field['width'])
                candidate = bytearray(b''.join(wires))
                base = len(wires[0]) + off
                candidate[base:base + width] = value
                pick = self.messages(codec)[first]['weight']
                status, records, error = self.mutate(engine, wires, bytes(candidate), 2,
                                                     scripted([pick, fields.index(field), 0]))
                self.assertEqual(status, 0, error)
                before, changed = unpack_records(records)
                self.assertEqual(before, wires[0])
                result_offset, result_width = self.field(codec, changed, field['locator'], field['type'], field['width'])
                self.assertEqual(changed[result_offset:result_offset + result_width], value)
                self.validate_sequence(codec, records)

    def test_prefix_rejects_service_without_handshake_then_enables_it(self):
        for codec, prefix, service in [('mms', ['cotp_cr', 'associate'], 'write'),
                                        ('enip', ['register'], 'send_rr'),
                                        ('opcua', ['hello', 'open_channel'], 'message'),
                                        ('iec104', ['start_act'], 'interrogation')]:
            with self.subTest(codec=codec), self.engine(codec) as engine:
                wire = self.wire(codec, service)
                result, _, _ = self.mutate(engine, [wire], wire, 1, scripted([0, 0, 0, 0]))
                self.assertEqual(result, -1)
                self.prefix(engine, [self.wire(codec, name) for name in prefix])
                successful = False
                for seed in range(1, 25):
                    if self.mutate(engine, [wire], wire, 1, deterministic(seed))[0] == 0:
                        successful = True
                        break
                self.assertTrue(successful, codec)
                self.prefix(engine, [wire], -1)
                self.assertEqual(self.mutate(engine, [wire], wire, 1, deterministic(seed))[0], -1)
                self.prefix(engine, [])

    def test_enip_binding_requires_pending_request_and_full_uint64_context_echo(self):
        context = 0xfedcba9876543210
        handle = 0x12345678
        register = bytearray(self.wire('enip', 'register'))
        register[12:20] = struct.pack('<Q', context)
        response = bytearray(self.wire('enip', 'register_response'))
        response[4:8] = struct.pack('<I', handle)
        response[12:20] = struct.pack('<Q', context)
        rr = self.wire('enip', 'send_rr')
        with self.engine('enip') as engine, self.engine('enip') as other:
            self.after(engine, bytes(response))
            self.before(engine, rr, -1)
            self.before(engine, bytes(register))
            spoof = bytearray(response);spoof[19] ^= 0x80
            self.after(engine, bytes(spoof))
            self.before(engine, rr, -1)
            self.after(engine, bytes(response[:13]))
            self.before(engine, rr, -1)
            self.after(engine, bytes(response[13:]))
            self.assertEqual(self.before(engine, rr)[4:8], struct.pack('<I', handle))
            self.before(other, rr, -1)
            replay = bytearray(response);replay[4:8] = struct.pack('<I', 0x87654321)
            self.after(engine, bytes(replay))
            self.assertEqual(self.before(engine, rr)[4:8], struct.pack('<I', handle))
            wires = [self.wire('enip', name) for name in PROFILES['enip'][1]]
            self.mutate(engine, wires, b''.join(wires), 1, deterministic(1))
            self.assertEqual(self.before(engine, rr)[4:8], struct.pack('<I', handle))
            self.lib.proto_session_begin(engine)
            self.before(engine, rr, -1)
            self.before(engine, bytes(register))
            self.after(engine, bytes(spoof) + bytes(response))
            self.assertEqual(self.before(engine, rr)[4:8], struct.pack('<I', handle))
            self.assertEqual(self.stats(engine)['correlated_responses'], 2)

    def test_opcua_response_ids_bind_channel_and_token_after_complete_frame(self):
        channel, token = 0x31415926, 0x27182818
        request_id, request_handle = 0x87654321, 0xabcdef01
        request = self.wire('opcua', 'open_channel')
        request = self.set_field('opcua', request, 'abs:75', 'uint32', struct.pack('<I', request_id))
        request = self.set_field('opcua', request, 'uabin:header.request_handle', 'uint32', struct.pack('<I', request_handle))
        response = self.wire('opcua', 'open_channel_response')
        response = self.set_fields('opcua', response, [
            (loc, 'uint32', struct.pack('<I', value))
            for loc, value in [('abs:8', channel), ('abs:75', request_id), ('uabin:token.channel_id', channel),
                               ('uabin:token.token_id', token), ('uabin:header.request_handle', request_handle)]])
        message = self.wire('opcua', 'message')
        with self.engine('opcua') as engine:
            self.after(engine, response)
            self.before(engine, message, -1)
            self.before(engine, self.wire('opcua', 'hello'))
            self.after(engine, self.wire('opcua', 'ack'))
            self.before(engine, request)
            spoof = self.set_field('opcua', response, 'abs:75', 'uint32', struct.pack('<I', request_id ^ 0x80000000))
            self.after(engine, spoof)
            self.before(engine, message, -1)
            spoof_handle = self.set_field('opcua', response, 'uabin:header.request_handle', 'uint32', struct.pack('<I', request_handle ^ 1))
            self.after(engine, spoof_handle)
            self.before(engine, message, -1)
            for byte in response[:-1]:
                self.after(engine, bytes([byte]))
            self.before(engine, message, -1)
            self.after(engine, response[-1:])
            bound = self.before(engine, message)
            self.assertEqual(bound[8:16], struct.pack('<II', channel, token))
            self.after(engine, response)
            self.assertEqual(self.stats(engine)['correlated_responses'], 1)
            self.lib.proto_session_begin(engine)
            self.before(engine, message, -1)
            self.before(engine, self.wire('opcua', 'hello'))
            self.after(engine, self.wire('opcua', 'ack'))
            self.before(engine, request)
            self.after(engine, spoof + response)
            self.assertEqual(self.before(engine, message)[8:16], struct.pack('<II', channel, token))

    def test_response_local_copy_uses_current_fields_before_cache_exists(self):
        protocol = copy.deepcopy(self.models['opcua'])
        response = next(message for message in protocol['messages'] if message['id'] == 'open_channel_response')
        response['dependencies'].append(dict(op='copy_from_message', target='token_channel', source='channel'))
        pp, sp = self.directory / 'response-local-copy.json', self.directory / 'response-local-state.json'
        pp.write_text(json.dumps(protocol));sp.write_text(json.dumps(self.states['opcua']))
        with self.engine('opcua', pp, sp) as engine:
            self.before(engine, self.wire('opcua', 'hello'))
            self.after(engine, self.wire('opcua', 'ack'))
            self.before(engine, self.wire('opcua', 'open_channel'))
            self.after(engine, self.wire('opcua', 'open_channel_response'))
            self.assertEqual(self.stats(engine)['correlated_responses'], 1)
            self.assertEqual(self.before(engine, self.wire('opcua', 'message'))[8:16], struct.pack('<II', 1, 1))

    def test_opcua_sequence_advances_across_services_and_resets_per_execution(self):
        def sequence(wire):
            offset, width = self.field('opcua', wire, 'uabin:sequence', 'uint32')
            return int.from_bytes(wire[offset:offset + width], 'little')

        with self.engine('opcua') as engine:
            self.before(engine, self.wire('opcua', 'hello'))
            self.after(engine, self.wire('opcua', 'ack'))
            opened = self.before(engine, self.wire('opcua', 'open_channel'))
            self.assertEqual(sequence(opened), 0)
            self.before(engine, self.wire('opcua', 'message'), -1)
            response = self.set_field('opcua', self.wire('opcua', 'open_channel_response'),
                                      'uabin:sequence', 'uint32', struct.pack('<I', 0xfedcba98))
            self.after(engine, response)
            self.assertEqual(sequence(self.before(engine, self.wire('opcua', 'message'))), 1)
            response = self.set_field('opcua', self.wire('opcua', 'message_response'),
                                      'uabin:sequence', 'uint32', struct.pack('<I', 0xffffffff))
            self.after(engine, response)
            simulated = [self.wire('opcua', name) for name in PROFILES['opcua'][1]]
            self.mutate(engine, simulated, b''.join(simulated), 1, deterministic(17))
            self.assertEqual(sequence(self.before(engine, self.wire('opcua', 'message'))), 2)
            self.after(engine, response)
            self.assertEqual(sequence(self.before(engine, self.wire('opcua', 'close_channel'))), 3)
            self.lib.proto_session_begin(engine)
            self.before(engine, self.wire('opcua', 'hello'))
            self.after(engine, self.wire('opcua', 'ack'))
            self.assertEqual(sequence(self.before(engine, self.wire('opcua', 'open_channel'))), 0)

    def test_session_begin_discards_partial_tcp_response(self):
        for codec, request_name, response_name, dependent in [
                ('enip', 'register', 'register_response', 'send_rr'),
                ('opcua', 'open_channel', 'open_channel_response', 'message')]:
            with self.subTest(codec=codec), self.engine(codec) as engine:
                if codec == 'opcua':
                    self.before(engine, self.wire(codec, 'hello'))
                    self.after(engine, self.wire(codec, 'ack'))
                request, response = self.wire(codec, request_name), self.wire(codec, response_name)
                self.before(engine, request)
                self.after(engine, response[:11])
                self.lib.proto_session_begin(engine)
                if codec == 'opcua':
                    self.before(engine, self.wire(codec, 'hello'))
                    self.after(engine, self.wire(codec, 'ack'))
                self.before(engine, request)
                self.after(engine, response[11:])
                self.before(engine, self.wire(codec, dependent), -1)
                self.after(engine, response)
                self.before(engine, self.wire(codec, dependent))


if __name__ == '__main__':
    unittest.main()
