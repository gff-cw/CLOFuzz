# BACnet/IP

Version: BACnet Stack 1.5.0 / ASHRAE 135.

Scope: BVLC Original-Unicast-NPDU; routed NPDU address parsing; unsegmented Who-Is with optional limits and ReadProperty with optional array index; application/context tag walking and invoke correlation.

Support: runtime scoped codec. BACnet is the live integration target; see `docs/bacnet-integration-test.md` for actual results.

Excluded: segmented APDUs; BACnet/SC; other services runtime encoding; BBMD/foreign-device lifecycle.

Each field names a source ID and confidence; see `evidence.yaml` for the source mapping and access limits. Static nested `structure_model` trees and state guard/action strings document semantics and are not executable code. Only the C runtime's documented operations execute. Static-only fixtures pass header/length checks, but are not exchanges validated with a target. In particular MMS fixtures omit complete session/presentation wrappers, and OPC UA secure-conversation fixtures omit complete service bodies.

Regenerate all files with `python3 tools/generate_protocol_models.py`; validate independently with `python3 tools/proto_spec_compiler.py --protocol protocols/bacnet_ip/protocol_spec.yaml --state protocols/bacnet_ip/state_transition.yaml --output-dir /tmp/bacnet_ip`.
