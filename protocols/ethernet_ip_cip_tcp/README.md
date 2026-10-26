# EtherNet/IP and CIP explicit TCP

Version: Encapsulation v1; public OpENer implementation.

Scope: EtherNet/IP TCP RegisterSession success/failure, UnregisterSession (no reply), SendRRData (NullAddress + UnconnectedData), SendUnitData (ConnectedAddress + ConnectedData with UInt16 class-3 sequence), complete GetAttributeSingle Identity Vendor-ID request/response layouts and encapsulation/CIP errors. SendUnitData requires an externally successful ForwardOpen establishing class-3 connection and supplying directional IDs; this model does not establish that prerequisite. Complete static explicit-message profile; no runtime encoder.

Support: static description; runtime encoder unavailable. Complete fixtures: 10/10; runtime request encoders: 0. BACnet is the sole StateAFL live integration target; see `docs/bacnet-integration-test.md`.

Excluded: ForwardOpen/ForwardClose fixture generation and automatic class-3 connection establishment (external prerequisite for SendUnitData); implicit UDP I/O; CIP Security; other CIP objects/services; full subscription-only ODVA normative conformance.

Complete means all bytes for the declared message/profile are present and checked by `tests/protocol/test_model_completeness.py`; it does not assert whole-standard conformance or successful exchanges with arbitrary products. A message marked `fragment` must never be presented as a valid service. `runtime_encode` records existing C runtime capability and is not an encoder selection switch. Nested `structure_model` trees and state guard/action strings are static descriptions.

Each field names a source ID and confidence; `evidence.yaml` records sources and access limits. The six-protocol completeness matrix, corrections and verification limits are in `docs/protocol-model-audit.md`.

Regenerate with `python3 tools/generate_protocol_models.py`; check complete fixtures with `python3 tests/protocol/test_model_completeness.py`; compile independently with `python3 tools/proto_spec_compiler.py --protocol protocols/ethernet_ip_cip_tcp/protocol_spec.yaml --state protocols/ethernet_ip_cip_tcp/state_transition.yaml --output-dir /tmp/ethernet_ip_cip_tcp`.
