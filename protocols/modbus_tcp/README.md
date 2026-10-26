# Modbus TCP

Version: Application Protocol 1.1b3; MBAP.

Scope: Modbus TCP MBAP plus FC01/02/03/04 reads, FC05/06 single writes, FC0F/10 multiple writes; all normal response layouts and generic exception layout; FC0F arbitrary 1..1968 coils including final-byte padding. Complete static profile; no runtime encoder.

Support: static description; runtime encoder unavailable. Complete fixtures: 19/19; runtime request encoders: 0. BACnet is the sole StateAFL live integration target; see `docs/bacnet-integration-test.md`.

Excluded: serial RTU; file-record and diagnostic function families.

Complete means all bytes for the declared message/profile are present and checked by `tests/protocol/test_model_completeness.py`; it does not assert whole-standard conformance or successful exchanges with arbitrary products. A message marked `fragment` must never be presented as a valid service. `runtime_encode` records existing C runtime capability and is not an encoder selection switch. Nested `structure_model` trees and state guard/action strings are static descriptions.

Each field names a source ID and confidence; `evidence.yaml` records sources and access limits. The six-protocol completeness matrix, corrections and verification limits are in `docs/protocol-model-audit.md`.

Regenerate with `python3 tools/generate_protocol_models.py`; check complete fixtures with `python3 tests/protocol/test_model_completeness.py`; compile independently with `python3 tools/proto_spec_compiler.py --protocol protocols/modbus_tcp/protocol_spec.yaml --state protocols/modbus_tcp/state_transition.yaml --output-dir /tmp/modbus_tcp`.
