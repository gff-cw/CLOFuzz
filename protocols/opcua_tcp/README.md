# OPC UA TCP

Version: OPC 10000 Parts 4/6 v1.05.

Scope: HEL/ACK/ERR/RHE transport and UASC OPN/MSG/CLO header structures, UA Binary/NodeId and lifecycle descriptions. Only SecurityPolicy None is described.

Support: static description; runtime encoder unavailable. BACnet is the live integration target; see `docs/bacnet-integration-test.md` for actual results.

Excluded: signed or encrypted security modes; complete service bodies; session activation; runtime chunk reassembly; CreateSession/ActivateSession request bodies and authentication are not generated.

Each field names a source ID and confidence; see `evidence.yaml` for the source mapping and access limits. Static nested `structure_model` trees and state guard/action strings document semantics and are not executable code. Only the C runtime's documented operations execute. Static-only fixtures pass header/length checks, but are not exchanges validated with a target. In particular MMS fixtures omit complete session/presentation wrappers, and OPC UA secure-conversation fixtures omit complete service bodies.

Regenerate all files with `python3 tools/generate_protocol_models.py`; validate independently with `python3 tools/proto_spec_compiler.py --protocol protocols/opcua_tcp/protocol_spec.yaml --state protocols/opcua_tcp/state_transition.yaml --output-dir /tmp/opcua_tcp`.
