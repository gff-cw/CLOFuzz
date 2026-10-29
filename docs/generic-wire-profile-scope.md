# Description-driven wire grammar: six-profile migration status

The new `stateafl.generic-wire` v1 files reside at `protocols/*/generic_wire.json`.
They are executable data for the protocol-independent C grammar engine, not
renamed copies of the older ICP-IR. Each file declares transport, TCP length
framing or UDP datagrams, request/response examples, a deterministic state graph,
response equality correlation where available, sequence bounds, and explicit
online eligibility. The offline generator `tools/build_generic_wire_profiles.py`
uses the six existing checked fixture sets to prepare these descriptions.
Python is only used before fuzzing; all wire parsing, encoding and mutation in
the StateAFL process must remain in C.

The v1 grammar is a strictly ordered struct of uint and bytes leaves.
Unsigned fields have width, endianness, role and bounds; fixed fields declare
an exact value. Derived integers support `size_of($message) + add` or the byte
size of any named field, including a later field. Byte lengths may reference an
earlier uint with a signed `add`; the result must fit the wire budget. See the
[language reference](generic-wire-language.md) for the general primitives. Exact
bytes slices preserve portions of the frozen fixture for which v1 has no
structural rule. Consequently a packet can pass this grammar while broader
protocol semantics remain unsupported. The unsupported array records every
original profile message that is not migrated, and an `online:false` package
must be rejected before starting a fuzz target.

The source inventories contain 71 messages: 14 have a v1 fixture grammar and
57 are listed as unsupported. That inventory counts message IDs, not complete
protocol services. Included messages still have the field and session gaps
below; omission from `unsupported` does not establish semantic completeness.

| Profile | v1 migrated requests / responses | Omitted IDs / source IDs | Online? | Critical missing capability |
| --- | --- | --- | --- | --- |
| BACnet/IP | ReadProperty / one exact ACK | 5 / 7 | No | LVT and variable tags, optional NPDU addresses, alternate ACK values, object/property response matching and error services. |
| IEC 60870-5-104 | STARTDT act, one fixed-sequence interrogation / matching confirmations | 7 / 11 | No | Live I/S sequence/window rules, COT variants, termination and arbitrary ASDUs. |
| IEC 61850 MMS/TCP | COTP CR / CC preamble | 12 / 14 | No | COTP reference matching, ISO session/presentation, ACSE, BER nested lengths and MMS services. |
| Modbus TCP | FC03 Read Holding, quantity fixed to one register / one two-byte normal response | 17 / 19 | Yes, scoped | Other function codes, exception responses, concurrent transaction database and variable register count. |
| EtherNet/IP CIP | RegisterSession / one success response | 8 / 10 | No | Session binding to later requests, CPF, CIP EPATH and ForwardOpen. |
| OPC UA TCP | Fixed-endpoint HEL / ACK | 8 / 10 | No | Buffer/version negotiation constraints, dynamic UA Binary values, channel/token binding, service bodies and multi-chunk messages. |

The Modbus `online:true` marker authorizes only the single FC03 grammar pair
above; it does not mark the full Modbus TCP description complete. Five other
packages have useful offline parse/encode fixtures but are explicitly blocked
from online generic mutation. The pre-existing six specialized C codecs remain
the only online route for the broader old profiles until their rules are moved
to executable generic grammar primitives and independently validated. A
name-only protocol switch or fixed example blob does not satisfy that goal.

Integer bounds are only the bounds explicitly declared in the grammar. C's
optional `values` array supplies HEAD mutation choices, not parse-time enum
membership. Fixed byte spans and arithmetic lengths do not validate nested
containers or other missing cross-field rules. State edges predict allowed
request sequences; they are separate from StateAFL's observed memory states.

Run `python3 tools/build_generic_wire_profiles.py --check` to compare all six
descriptions byte-for-byte with regenerated data without writing files. The
generator rejects missing selected source messages and overlapping/truncated
selected fields instead of silently emitting a reduced grammar. Run it without
`--check` to regenerate the files; that operation does not authorize expanding
online eligibility.

This is not a general YAML-to-generic-wire compiler. The script reads old
`protocol_ir.json` fixtures but not `state_ir.json`; it obtains state edges and
correlations from its own six-profile tables. Derived fields are approximated
as fixture total-size additions, and unsupported structure is frozen into exact
byte slices. Editing old YAML state, dependency or binding declarations does
not establish an equivalent new grammar. The templates and schemas retain
their [separate format scopes](../protocols/templates/README.md).

Run `python3 tools/check_generic_wire_profiles.py` to verify the six package
IDs, selected fixture bytes, field bounds, derived lengths, framing, correlation
references, deterministic state edges and exhaustive unsupported-message
inventories. It rejects unknown schema attributes, invalid integer encodings,
invalid byte lengths and violations of constraints on non-fixed leaves as the C
grammar compiler/parser do. It also rejects orphan correlation rules, missing
request-pair coverage on shared responses and same-direction grammar ambiguity
at each declared example. This finite example check is not a proof that all
possible accepted messages are unambiguous. JSON loading also rejects non-UTF-8
input, floats and non-JSON numeric constants, out-of-range integers, duplicate
decoded keys and invalid Unicode scalars, with native byte/node/depth budgets.
Profile checks additionally require matching source
fixtures, equal example correlation values, explicit limitations and the current
online policy. It is an independent Python check, not an invocation of the C loader.

`tests/generic-wire/test_generic_profiles.c` compiles and roundtrips all 14
grammars using the production C API, checks editable scalar bounds, and rejects
fixed/derived violations, truncated packets and trailing bytes. This test does
not load offline packages into an online engine or exercise a target. The
separate Modbus runtime test checks TCP fragmentation and scalar correlation;
neither test proves campaign coverage gains, broader protocol conformance or
compatibility with a particular server.
