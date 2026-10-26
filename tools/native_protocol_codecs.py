"""Use the same bounded C wire codecs when checking non-BACnet descriptions.

Compilation happens once per compiler process, in a private temporary directory.
StateAFL links these sources directly; no Python runs in its mutation loop.
Independent fixture readers remain in tests/protocol/test_model_completeness.py.
"""
import ctypes
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
NAMES = ('modbus', 'iec104', 'mms', 'enip', 'opcua')
TYPES = ('uint8', 'uint16', 'uint24', 'uint32', 'uint64', 'bytes', 'string',
         'bacnet_tags', 'ber_tlv', 'epath', 'nodeid')
_library = None
_temporary = None


def library():
    global _library, _temporary
    if _library is None:
        _temporary = tempfile.TemporaryDirectory(prefix='stateafl-codecs-')
        binary = Path(_temporary.name) / 'codecs.so'
        command = [os.environ.get('CC', 'cc'), '-std=c11', '-O2', '-shared', '-fPIC',
                   '-I', str(ROOT), *(str(ROOT / f'protocol_codec_{n}.c') for n in NAMES),
                   '-o', str(binary)]
        completed = subprocess.run(command, capture_output=True, text=True)
        if completed.returncode:
            raise ValueError('cannot build native description validator (C11 compiler required): ' + completed.stderr[-2000:])
        _library = ctypes.CDLL(str(binary))
    return _library


def inspect(codec, wire, fields):
    lib = library()
    data = (ctypes.c_uint8 * len(wire)).from_buffer_copy(wire)
    error = ctypes.create_string_buffer(256)
    validate = getattr(lib, f'pc_{codec}_validate')
    validate.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t]
    if validate(data, len(wire), error, len(error)) < 0:
        raise ValueError(error.value.decode(errors='replace'))
    locate = getattr(lib, f'pc_{codec}_field')
    locate.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p,
                      ctypes.c_int, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
                      ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t]
    result = {}
    for field in fields:
        offset, width = ctypes.c_size_t(), ctypes.c_size_t()
        status = locate(data, len(wire), field['locator'].encode(), TYPES.index(field['type']),
                        field['width'], ctypes.byref(offset), ctypes.byref(width), error, len(error))
        if status < 0:
            raise ValueError(field['id'] + ': ' + error.value.decode(errors='replace'))
        if status:
            if offset.value > len(wire) or width.value > len(wire) - offset.value:
                raise ValueError('native locator exceeded message')
            result[(field['locator'], field['type'], field['width'])] = (offset.value, width.value)
    return result


def same_kind(codec, wire, example):
    function = getattr(library(), f'pc_{codec}_same_kind')
    function.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t]
    return bool(function(wire, len(wire), example, len(example)))
