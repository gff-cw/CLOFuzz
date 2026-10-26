# IEC 61850 MMS over TCP

Version: RFC1006 / libIEC61850 v1.6 profile.

Scope: Complete TPKT/COTP TP0, session/presentation normal-mode association, ACSE AARQ/AARE with embedded MMS initiate, VMD-domain GetNameList, one domain-specific named-variable Read/Write, MMS conclude and ACSE/session release, all successful request/response layouts. Bounded runtime codec with BER definite lengths and structural repair.

Support: runtime scoped codec. Complete fixtures: 14/14; runtime request encoders: 7. BACnet is the industrial protocol implementation used for live integration; the five TCP profiles also have instrumented local fixture tests; see `docs/bacnet-integration-test.md`.

Latest test acceptance is recorded in [task recovery](../../docs/task-recovery.md); fixture presence does not imply acceptance.

Excluded: full IEC61850 ACSI mapping; reports/GOOSE/SV; generalized arrays/alternate access and data-set services; arbitrary ACSE authentication; association rejection/abort and MMS confirmed-error/reject fixtures unverified; TLS; arbitrary BER container generation.

Complete means all bytes for the declared message/profile are present and checked by `tests/protocol/test_model_completeness.py`; it does not assert whole-standard conformance or successful exchanges with arbitrary products. A message marked `fragment` must never be presented as a valid service. `runtime_encode` records existing C runtime capability and is not an encoder selection switch. Nested `structure_model` trees and state guard/action strings are static descriptions.

Each field names a source ID and confidence; `evidence.yaml` records sources and access limits. The six-protocol completeness matrix, corrections and verification limits are in `docs/protocol-model-audit.md`.

Non-BACnet description compilation builds the bounded native validator with `CC` (or `cc`); a C11 compiler, `protocol_codecs.h`, `tools/native_protocol_codecs.py`, and all five `protocol_codec_*.c` sources are required. StateAFL links the codecs directly and runs no Python during mutation.

Regenerate with `python3 tools/generate_protocol_models.py`; check complete fixtures with `python3 tests/protocol/test_model_completeness.py`; compile independently with `python3 tools/proto_spec_compiler.py --protocol protocols/iec61850_mms_tcp/protocol_spec.yaml --state protocols/iec61850_mms_tcp/state_transition.yaml --output-dir /tmp/iec61850_mms_tcp`.
