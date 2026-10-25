# Modbus TCP

Version: Application Protocol 1.1b3; MBAP.

Scope: Functions 01-06, 0F, 10, their field layouts, read-register response and exception response; no serial RTU CRC.

Support: static description; runtime encoder unavailable. BACnet is the live integration target; see `docs/bacnet-integration-test.md` for actual results.

Excluded: serial RTU; file-record and diagnostic function families.

Each field names a source ID and confidence; see `evidence.yaml` for the source mapping and access limits. Static nested `structure_model` trees and state guard/action strings document semantics and are not executable code. Only the C runtime's documented operations execute. Static-only fixtures pass header/length checks, but are not exchanges validated with a target. In particular MMS fixtures omit complete session/presentation wrappers, and OPC UA secure-conversation fixtures omit complete service bodies.

Regenerate all files with `python3 tools/generate_protocol_models.py`; validate independently with `python3 tools/proto_spec_compiler.py --protocol protocols/modbus_tcp/protocol_spec.yaml --state protocols/modbus_tcp/state_transition.yaml --output-dir /tmp/modbus_tcp`.
