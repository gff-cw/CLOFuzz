# BACnet/IP

Version: BACnet Stack 1.5.0 / ASHRAE 135.

Scope: BVLC Original-Unicast-NPDU, optional routed NPDU addresses; unsegmented Who-Is/I-Am; ReadProperty request/ACK/Error and Reject/server-Abort. Runtime generates only Who-Is and ReadProperty requests; response layouts are complete static descriptions.

Support: runtime scoped codec. Complete fixtures: 7/7; runtime request encoders: 2. BACnet is the industrial protocol implementation used for live integration; the five TCP profiles also have instrumented local fixture tests; see `docs/bacnet-integration-test.md`.

Excluded: segmented APDUs; BACnet/SC; other services runtime encoding; BBMD/foreign-device lifecycle.

Complete means all bytes for the declared message/profile are present and checked by `tests/protocol/test_model_completeness.py`; it does not assert whole-standard conformance or successful exchanges with arbitrary products. A message marked `fragment` must never be presented as a valid service. `runtime_encode` records existing C runtime capability and is not an encoder selection switch. Nested `structure_model` trees and state guard/action strings are static descriptions.

Each field names a source ID and confidence; `evidence.yaml` records sources and access limits. The six-protocol completeness matrix, corrections and verification limits are in `docs/protocol-model-audit.md`.

Non-BACnet description compilation builds the bounded native validator with `CC` (or `cc`); a C11 compiler, `protocol_codecs.h`, `tools/native_protocol_codecs.py`, and all five `protocol_codec_*.c` sources are required. StateAFL links the codecs directly and runs no Python during mutation.

Regenerate with `python3 tools/generate_protocol_models.py`; check complete fixtures with `python3 tests/protocol/test_model_completeness.py`; compile independently with `python3 tools/proto_spec_compiler.py --protocol protocols/bacnet_ip/protocol_spec.yaml --state protocols/bacnet_ip/state_transition.yaml --output-dir /tmp/bacnet_ip`.
