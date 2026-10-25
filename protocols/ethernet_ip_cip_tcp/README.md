# EtherNet/IP and CIP explicit TCP

Version: Encapsulation v1; public OpENer implementation.

Scope: Encapsulation lifecycle, SendRRData/SendUnitData CPF and CIP path description. No implicit UDP I/O.

Support: static description; runtime encoder unavailable. BACnet is the live integration target; see `docs/bacnet-integration-test.md` for actual results.

Excluded: implicit UDP I/O; ForwardOpen runtime binding; CIP Security; subscription-only ODVA details not independently verified.

Each field names a source ID and confidence; see `evidence.yaml` for the source mapping and access limits. Static nested `structure_model` trees and state guard/action strings document semantics and are not executable code. Only the C runtime's documented operations execute. Static-only fixtures pass header/length checks, but are not exchanges validated with a target. In particular MMS fixtures omit complete session/presentation wrappers, and OPC UA secure-conversation fixtures omit complete service bodies.

Regenerate all files with `python3 tools/generate_protocol_models.py`; validate independently with `python3 tools/proto_spec_compiler.py --protocol protocols/ethernet_ip_cip_tcp/protocol_spec.yaml --state protocols/ethernet_ip_cip_tcp/state_transition.yaml --output-dir /tmp/ethernet_ip_cip_tcp`.
