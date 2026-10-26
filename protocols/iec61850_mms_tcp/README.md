# IEC 61850 MMS over TCP

Version: RFC1006 / libIEC61850 v1.6 profile.

Scope: Complete TPKT/COTP TP0, session/presentation normal-mode association, ACSE AARQ/AARE with embedded MMS initiate, VMD-domain GetNameList, one domain-specific named-variable Read/Write, MMS conclude and ACSE/session release, all successful request/response layouts. BER definite lengths; no runtime encoder.

Support: static description; runtime encoder unavailable. Complete fixtures: 14/14; runtime request encoders: 0. BACnet is the sole StateAFL live integration target; see `docs/bacnet-integration-test.md`.

Excluded: full IEC61850 ACSI mapping; reports/GOOSE/SV; generalized arrays/alternate access and data-set services; arbitrary ACSE authentication; association rejection/abort and MMS confirmed-error/reject fixtures unverified; TLS; runtime BER encoding.

Complete means all bytes for the declared message/profile are present and checked by `tests/protocol/test_model_completeness.py`; it does not assert whole-standard conformance or successful exchanges with arbitrary products. A message marked `fragment` must never be presented as a valid service. `runtime_encode` records existing C runtime capability and is not an encoder selection switch. Nested `structure_model` trees and state guard/action strings are static descriptions.

Each field names a source ID and confidence; `evidence.yaml` records sources and access limits. The six-protocol completeness matrix, corrections and verification limits are in `docs/protocol-model-audit.md`.

Regenerate with `python3 tools/generate_protocol_models.py`; check complete fixtures with `python3 tests/protocol/test_model_completeness.py`; compile independently with `python3 tools/proto_spec_compiler.py --protocol protocols/iec61850_mms_tcp/protocol_spec.yaml --state protocols/iec61850_mms_tcp/state_transition.yaml --output-dir /tmp/iec61850_mms_tcp`.
