# OPC UA TCP

Version: OPC10000 Part4/6 v1.05 / asyncua interoperability profile.

Scope: Complete HEL/ACK/ERR/RHE and single-final-chunk UASC SecurityPolicy None Issue OpenSecureChannel request/response, GetEndpoints Discovery request/response, ServiceFault, implementation-profile CloseSecureChannel. Complete UA Binary headers and nested endpoint/token arrays; no Session services or runtime encoder.

Support: static description; runtime encoder unavailable. Complete fixtures: 10/10; runtime request encoders: 0. BACnet is the sole StateAFL live integration target; see `docs/bacnet-integration-test.md`.

Excluded: signing/encryption and certificates; OpenSecureChannel Renew and token-overlap behavior; CreateSession/ActivateSession and authenticated/session services; intermediate/abort chunks and runtime reassembly; whole-standard conformance; CLO normative wording difference unresolved.

Complete means all bytes for the declared message/profile are present and checked by `tests/protocol/test_model_completeness.py`; it does not assert whole-standard conformance or successful exchanges with arbitrary products. A message marked `fragment` must never be presented as a valid service. `runtime_encode` records existing C runtime capability and is not an encoder selection switch. Nested `structure_model` trees and state guard/action strings are static descriptions.

Each field names a source ID and confidence; `evidence.yaml` records sources and access limits. The six-protocol completeness matrix, corrections and verification limits are in `docs/protocol-model-audit.md`.

Regenerate with `python3 tools/generate_protocol_models.py`; check complete fixtures with `python3 tests/protocol/test_model_completeness.py`; compile independently with `python3 tools/proto_spec_compiler.py --protocol protocols/opcua_tcp/protocol_spec.yaml --state protocols/opcua_tcp/state_transition.yaml --output-dir /tmp/opcua_tcp`.
