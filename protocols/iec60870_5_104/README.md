# IEC 60870-5-104

Version: IEC 60870-5-104; lib60870 profile.

Scope: I/S/U APCI; STARTDT, STOPDT, TESTFR and single-object C_IC_NA_1 ASDU; 2-byte COT/CA and 3-byte IOA.

Support: static description; runtime encoder unavailable. BACnet is the live integration target; see `docs/bacnet-integration-test.md` for actual results.

Excluded: other ASDU payload types; TLS; multi-object runtime generation.

Each field names a source ID and confidence; see `evidence.yaml` for the source mapping and access limits. Static nested `structure_model` trees and state guard/action strings document semantics and are not executable code. Only the C runtime's documented operations execute. Static-only fixtures pass header/length checks, but are not exchanges validated with a target. In particular MMS fixtures omit complete session/presentation wrappers, and OPC UA secure-conversation fixtures omit complete service bodies.

Regenerate all files with `python3 tools/generate_protocol_models.py`; validate independently with `python3 tools/proto_spec_compiler.py --protocol protocols/iec60870_5_104/protocol_spec.yaml --state protocols/iec60870_5_104/state_transition.yaml --output-dir /tmp/iec60870_5_104`.
