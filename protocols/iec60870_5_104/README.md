# IEC 60870-5-104

Version: IEC 60870-5-104; lib60870 profile.

Scope: IEC104 APCI I/S/U; STARTDT/STOPDT/TESTFR; single-object C_IC_NA_1 global/group interrogation request, positive/negative activation confirmation and termination; COT/CA/IOA widths 2/2/3. Other data ASDUs excluded. Complete static profile; no runtime encoder.

Support: static description; runtime encoder unavailable. Complete fixtures: 11/11; runtime request encoders: 0. BACnet is the sole StateAFL live integration target; see `docs/bacnet-integration-test.md`.

Excluded: other ASDU payload types; TLS; multi-object runtime generation.

Complete means all bytes for the declared message/profile are present and checked by `tests/protocol/test_model_completeness.py`; it does not assert whole-standard conformance or successful exchanges with arbitrary products. A message marked `fragment` must never be presented as a valid service. `runtime_encode` records existing C runtime capability and is not an encoder selection switch. Nested `structure_model` trees and state guard/action strings are static descriptions.

Each field names a source ID and confidence; `evidence.yaml` records sources and access limits. The six-protocol completeness matrix, corrections and verification limits are in `docs/protocol-model-audit.md`.

Regenerate with `python3 tools/generate_protocol_models.py`; check complete fixtures with `python3 tests/protocol/test_model_completeness.py`; compile independently with `python3 tools/proto_spec_compiler.py --protocol protocols/iec60870_5_104/protocol_spec.yaml --state protocols/iec60870_5_104/state_transition.yaml --output-dir /tmp/iec60870_5_104`.
