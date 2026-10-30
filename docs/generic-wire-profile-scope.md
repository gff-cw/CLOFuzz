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

## Structured protocol capability gap taxonomy (G03)

Protocol capabilities are formally scoped across message, service, field,
and session boundaries. The presence of frozen fixture bytes in an offline
grammar does not constitute capability support. The six core gap categories
below are tracked as explicit non-conformance items:

### 1. Error response gap (`GAP_ERROR_RESPONSE`)
* **Modbus TCP**: Only normal 2-byte register response is modeled; exception
  responses (FC 0x83, exception codes 01–04) are unexpressed.
* **BACnet/IP**: Error-PDU, Reject-PDU, and Abort-PDU response layouts are absent.
* **IEC 104**: Negative activation confirmations and mirrored mirror rejections are unexpressed.
* **IEC 61850 MMS**: ServiceError, ConfirmedErrorPDU, and RejectPDU are unexpressed.
* **EtherNet/IP**: Encapsulation status error codes and CIP routing error statuses are unexpressed.
* **OPC UA**: ServiceFault and error chunk (`ERR`) layouts are unexpressed.

### 2. Variable quantity and dynamic sizing gap (`GAP_VARIABLE_QUANTITY`)
* **Modbus TCP**: Register count is locked to exactly 1 (2 data bytes). Arbitrary
  read quantities (1..125) and write masks are unexpressed.
* **BACnet/IP**: Variable-length object property lists, strings, and octet strings are unexpressed.
* **IEC 104**: Variable structure qualifiers ($VSQ > 1$) with multi-object ASDUs are unexpressed.
* **IEC 61850 MMS**: Arrays of named variables in Read/Write services are unexpressed.
* **EtherNet/IP**: Multi-service packets and variable-length CIP paths are unexpressed.
* **OPC UA**: Dynamic array dimensions (EndpointDescription arrays, UserTokenPolicy arrays) are unexpressed.

### 3. Concurrent transaction gap (`GAP_CONCURRENT_TRANSACTION`)
* **Modbus TCP**: Single pending transaction only. Concurrent pipelined transaction IDs
  over a shared TCP stream are unexpressed.
* **BACnet/IP**: Concurrent invoke IDs for unconfirmed/confirmed transactions are unexpressed.
* **IEC 104**: Live $V(S) / V(R)$ sequence window accounting and simultaneous interrogation/commands are unexpressed.
* **IEC 61850 MMS**: Multiple concurrent invoke IDs are unexpressed.
* **EtherNet/IP**: Concurrent CIP transport class 3 connections are unexpressed.
* **OPC UA**: Concurrent request handles across multiple secure channels are unexpressed.

### 4. Server session value and dynamic binding gap (`GAP_SERVER_SESSION_VALUE`)
* **BACnet/IP**: Dynamic device instance discovery and router address learning are unexpressed.
* **IEC 61850 MMS**: Negotiated association parameters (Max PDU Size, Max Services, Nesting Level)
  restricting subsequent PDUs are unexpressed.
* **EtherNet/IP**: Session Handle returned by `RegisterSession` dynamically required in
  `SendRRData` / `SendUnitData` cannot be propagated without dedicated session binding.
* **OPC UA**: Dynamic `ChannelId`, `TokenId`, and security nonces from `OpenSecureChannel`
  cannot be dynamically bound to subsequent payload headers in generic-wire v1.

### 5. Nested container and complex encoding gap (`GAP_NESTED_CONTAINER`)
* **BACnet/IP**: Tag-Length-Value (LVT) context/application tags and constructed objects are unexpressed.
* **IEC 104**: CP56Time2a 7-octet binary timestamps and multi-octet ASDU qualifiers are unexpressed.
* **IEC 61850 MMS**: Deeply nested ASN.1/BER tag-length trees and indefinite length forms are unexpressed.
* **EtherNet/IP**: Common Packet Format (CPF) type-length-value encapsulation items are unexpressed.
* **OPC UA**: Structured UA Binary variants (NodeId, QualifiedName, LocalizedText) are unexpressed.

### 6. Multi-chunk segmentation gap (`GAP_MULTI_CHUNK`)
* **BACnet/IP**: Segmented request/response sequences with window sizes and sequence numbers are unexpressed.
* **IEC 104**: Spontaneous multi-ASDU burst transmissions are unexpressed.
* **IEC 61850 MMS**: TPKT multi-buffer PDU reassembly is unexpressed.
* **EtherNet/IP**: Fragmented CIP explicit transfers are unexpressed.
* **OPC UA**: Multi-chunk message sequences (`MSG` continuations 'C' ending in 'F') are unexpressed.

Because these critical gaps exist, all five non-Modbus packages are strictly
enforced as `online: false`. The runtime and profile checkers reject any attempt
to execute them online.

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
