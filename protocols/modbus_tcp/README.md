# Modbus TCP

Version: Application Protocol 1.1b3; MBAP.

Scope: Modbus TCP MBAP plus FC01/02/03/04 reads, FC05/06 single writes, FC0F/10 multiple writes; all normal response layouts and generic exception layout; FC0F arbitrary 1..1968 coils including final-byte padding. Bounded runtime codec and structural repair.

Support: runtime scoped codec. Complete fixtures: 19/19; runtime request encoders: 9. BACnet is the industrial protocol implementation used for live integration; the five TCP profiles also have instrumented local fixture tests; see `docs/bacnet-integration-test.md`.

Latest test acceptance is recorded in [task recovery](../../docs/task-recovery.md); fixture presence does not imply acceptance.

Excluded: serial RTU; file-record and diagnostic function families.

Complete means all bytes for the declared message/profile are present and checked by `tests/protocol/test_model_completeness.py`; it does not assert whole-standard conformance or successful exchanges with arbitrary products. A message marked `fragment` must never be presented as a valid service. `runtime_encode` records existing C runtime capability and is not an encoder selection switch. Nested `structure_model` trees and state guard/action strings are static descriptions.

Each field names a source ID and confidence; `evidence.yaml` records sources and access limits. The six-protocol completeness matrix, corrections and verification limits are in `docs/protocol-model-audit.md`.

Non-BACnet description compilation builds the bounded native validator with `CC` (or `cc`); a C11 compiler, `protocol_codecs.h`, `tools/native_protocol_codecs.py`, and all five `protocol_codec_*.c` sources are required. StateAFL links the codecs directly and runs no Python during mutation.

Regenerate with `python3 tools/generate_protocol_models.py`; check complete fixtures with `python3 tests/protocol/test_model_completeness.py`; compile independently with `python3 tools/proto_spec_compiler.py --protocol protocols/modbus_tcp/protocol_spec.yaml --state protocols/modbus_tcp/state_transition.yaml --output-dir /tmp/modbus_tcp`.
