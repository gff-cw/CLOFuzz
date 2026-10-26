#!/usr/bin/env python3
"""Reproduce the scoped Python/C BACnet decoder audit; no live target is used.

Run from any directory. The temporary shared library is deleted on completion.
Accepted inputs demonstrate decoder agreement, not BACnet service conformance.
"""
import ctypes
import hashlib
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from proto_spec_compiler import SpecError, bacnet_example_fields

SEED = 111
CASES = 15000
LOCATORS = [
    "bvlc.type", "bvlc.function", "bvlc.length", "npdu.version", "npdu.control",
    "apdu.type", "apdu.service", "apdu.invoke", "apdu.max_apdu", "apdu.content",
    "bacnet.object", "bacnet.property", "bacnet.array",
]
TAG_FIXTURES = [
    "", "09011902", "0c0200007b194d", "0c0200007b194d2901",
    "c40200007b2205c491032100", "3e21013f", "3f", "f90100", "3e4e21014f3f",
]


def candidate(rng, index):
    control = rng.choice([0, 4, 32, 8, 40, 0x80, 0xd0])
    npdu = bytearray([1, control])
    for bit in (32, 8):
        if control & bit:
            size = rng.randrange(4)
            npdu.extend(bytes([0, 1, size]) + rng.randbytes(size))
    if control & 32:
        npdu.append(255)
    kind = rng.choice([0, 1, 2, 3, 5, 6, 7, 4])
    flags = rng.choice([0, 0, 0, 1, 2, 8])
    apdu = bytearray([(kind << 4) | flags])
    if kind == 0:
        apdu.extend([5, 1, rng.choice([12, 8, 0])])
    elif kind == 1:
        apdu.append(rng.choice([8, 0, 12]))
    else:
        apdu.extend([1, rng.choice([12, 8, 0])])
    tail = (bytes.fromhex(rng.choice(TAG_FIXTURES)) if index % 3 == 0
            else rng.randbytes(rng.randrange(25)))
    wire = bytearray([0x81, rng.choice([10, 11, 0]), 0, 0]) + npdu + apdu + tail
    wire[2:4] = len(wire).to_bytes(2, "big")
    return wire


def main():
    rng = random.Random(SEED)
    accepted = rejected = comparisons = differences = 0
    samples = []

    def mismatch(index, wire, details):
        nonlocal differences
        differences += 1
        if len(samples) < 20:
            samples.append(dict(case=index, wire_hex=wire.hex(), **details))

    with tempfile.TemporaryDirectory(prefix="template-parser-differential-") as temporary:
        library = Path(temporary) / "protocol_runtime.so"
        subprocess.run([
            "clang", "-O1", "-shared", "-fPIC", "-I", str(ROOT),
            str(ROOT / "protocol_runtime.c"), "-o", str(library),
        ], check=True, capture_output=True, text=True)
        decoder = ctypes.CDLL(str(library)).proto_bacnet_field
        decoder.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_char_p, ctypes.c_size_t,
        ]
        decoder.restype = ctypes.c_int

        for index in range(CASES):
            wire = candidate(rng, index)
            assert len(wire) >= 8
            try:
                fields, _, _ = bacnet_example_fields(wire, "audit.example")
                python_accepts = True
            except SpecError:
                fields, python_accepts = {}, False
            buffer = ctypes.create_string_buffer(bytes(wire))
            error = ctypes.create_string_buffer(256)
            offset, width = ctypes.c_size_t(), ctypes.c_size_t()
            result = decoder(buffer, len(wire), b"apdu.content",
                             ctypes.byref(offset), ctypes.byref(width), error, len(error))
            c_accepts = result == 1
            if python_accepts != c_accepts:
                mismatch(index, wire, dict(kind="acceptance", python=python_accepts,
                                          c=c_accepts, c_error=error.value.decode()))
                continue
            if not python_accepts:
                rejected += 1
                continue
            accepted += 1
            for locator in LOCATORS:
                comparisons += 1
                result = decoder(buffer, len(wire), locator.encode(),
                                 ctypes.byref(offset), ctypes.byref(width), error, len(error))
                expected = fields.get(locator)
                actual = (offset.value, width.value) if result == 1 else None
                if (result != (0 if expected is None else 1)) or actual != expected:
                    mismatch(index, wire, dict(kind="locator", locator=locator,
                                              python=expected, c=actual, c_result=result,
                                              c_error=error.value.decode()))

    report = dict(
        seed=SEED, cases=CASES, accepted=accepted, rejected=rejected,
        locator_count=len(LOCATORS), locator_comparisons=comparisons,
        discrepancies=differences, discrepancy_samples=samples, locators=LOCATORS,
        source_sha256={
            name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            for name in ("tools/proto_spec_compiler.py", "protocol_runtime.c")
        },
        interpretation="Scoped decoder agreement; no claim of live service conformance.",
    )
    print(json.dumps(report, indent=2))
    return 1 if differences else 0


if __name__ == "__main__":
    sys.exit(main())
