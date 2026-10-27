# Seventh protocol acceptance fixture

`fictional_protocol.json` is deliberately not one of StateAFL's six industrial
protocols. Its wire format has a fixed magic/opcode, a derived big-endian body
length, a mutable HEAD serial, and a variable CONTENT payload. It proves that
the production generic C API can parse and reencode a description without a
seventh protocol-specific codec. No industrial conformance claim follows.

The C harness checks valid and malformed fixtures, read-only roundtrips,
HEAD/CONTENT edits, derived-length repair, fixed-byte preservation, and failed
edits leaving the packet unchanged. `pulse` is a no-response UDP request with
a declared `ready -> ready` transition, so the StateAFL runtime can exercise
message-level SEQUENCE operations on LE32 replay records.

Run the strict C tests from the repository root:

```sh
make check-generic-wire
```

The equivalent individual commands are:

```sh
clang -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined \
  -fno-omit-frame-pointer -I. tests/generic-wire/test_generic_wire.c \
  generic_wire.c native_json.c -o /tmp/test-generic-wire
/tmp/test-generic-wire tests/generic-wire/fictional_protocol.json

clang -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined \
  -fno-omit-frame-pointer -I. tests/generic-wire/test_generic_runtime.c \
  protocol_runtime.c generic_runtime.c generic_wire.c native_json.c \
  protocol_codec_{modbus,iec104,mms,enip,opcua}.c -o /tmp/test-generic-runtime
/tmp/test-generic-runtime tests/generic-wire/fictional_protocol.json

clang -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined \
  -fno-omit-frame-pointer -I. tests/generic-wire/test_generic_profiles.c \
  generic_wire.c native_json.c -o /tmp/test-generic-profiles
/tmp/test-generic-profiles protocols/*/generic_wire.json

clang -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined \
  -fno-omit-frame-pointer -I. tests/generic-wire/test_generic_modbus.c \
  protocol_runtime.c generic_runtime.c generic_wire.c native_json.c \
  protocol_codec_{modbus,iec104,mms,enip,opcua}.c -o /tmp/test-generic-modbus
/tmp/test-generic-modbus protocols/modbus_tcp/generic_wire.json
```

The six-profile roundtrip test checks all 14 currently modeled request/response
examples. Five of the six descriptions are offline-only in generic-wire v1, so
the roundtrip result does not imply they may run online in the generic engine.
The Modbus C test checks the single online FC03 request/response profile,
including a fragmented TCP response and request/response field correlation.

For a local end-to-end check, compile `fixture_udp_server.c` with StateAFL's
`afl-clang-fast`, create a LE32 replay record containing `a700050100015566`,
and run `afl-fuzz -d -N udp://127.0.0.1/PORT -D 50000 -K -m none -t 1000
--generic-spec tests/generic-wire/fictional_protocol.json --mutation-mode valid
--mutation-layers head,content,sequence --protocol-schedule adaptive -- SERVER PORT`
with a fresh input/output directory. The server checks the described header,
length, opcode and serial without linking the grammar engine. A bounded live
run must inspect actual candidate replays, mutation logs and scheduler feedback;
three mutation counters by themselves do not establish format preservation or
coverage improvement.

`python3 tests/generic-wire/run_live.py --output /tmp/generic-live-new
--seconds 12 --state-aware` runs that bounded acceptance automatically. It
requires a fresh output directory, the built StateAFL binaries/toolchain and
permission to disable ASLR per process with `setarch -R`. The controller is
Python; the wire interpreter, executor, three mutation layers and feedback
consumer all execute in C. See [the language and feedback reference](../../docs/generic-wire-language.md).
