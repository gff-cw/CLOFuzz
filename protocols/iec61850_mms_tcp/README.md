# IEC 61850 MMS over TCP

Version: IEC 61850-8-1 / ISO 9506 / RFC 1006.

Scope: Transport COTP plus declarative ACSE/Initiate/confirmed GetNameList Read Write envelopes; nested BER; full session/presentation association requires an external complete codec.

Support: static description; runtime encoder unavailable. BACnet is the live integration target; see `docs/bacnet-integration-test.md` for actual results.

Excluded: complete session/presentation codec; runtime BER service encoding; all abstract IEC61850 services; TLS.

Each field names a source ID and confidence; see `evidence.yaml` for the source mapping and access limits. Static nested `structure_model` trees and state guard/action strings document semantics and are not executable code. Only the C runtime's documented operations execute. Static-only fixtures pass header/length checks, but are not exchanges validated with a target. In particular MMS fixtures omit complete session/presentation wrappers, and OPC UA secure-conversation fixtures omit complete service bodies.

Regenerate all files with `python3 tools/generate_protocol_models.py`; validate independently with `python3 tools/proto_spec_compiler.py --protocol protocols/iec61850_mms_tcp/protocol_spec.yaml --state protocols/iec61850_mms_tcp/state_transition.yaml --output-dir /tmp/iec61850_mms_tcp`.
