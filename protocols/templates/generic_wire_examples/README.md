# generic-wire v1 authoring catalog

The formal starter is [`../generic_wire.template.json`](../generic_wire.template.json),
with the online structural contract in
[`../../schema/generic_wire.schema.json`](../../schema/generic_wire.schema.json).
It is concrete, editable JSON: the fictional example is deliberately loadable,
and its bytes must be replaced with the intended protocol's actual wire model.
It is independent of old codec YAML and of offline-layout/observation templates.

| Example | Wire transport | Response contract | Included input |
| --- | --- | --- | --- |
| [udp_oneway](udp_oneway/README.md) | one message per UDP datagram | no response | one request and a repeated request replay |
| [udp_request_response](udp_request_response/README.md) | one message per UDP datagram | complete response echoes the integer serial | request-only replays plus separate response wire fixture |
| [tcp_request_response](tcp_request_response/README.md) | length uint16 at offset 1, big endian, frame bytes = value + 3 | serial correlation; fragmented/coalesced TCP processing | request-only replays plus separate response wire fixture |

Create a complete editable input package in a new directory:

```sh
python3 tools/generic_template_catalog.py --base tcp_request_response \
  --protocol-id my_protocol --output-dir /tmp/my-generic-protocol
```

The command checks structure and saved asset identity, copies through a
same-parent staging directory, and publishes a complete description/fixture/
seed/manifest package. It never compiles or starts a target, and refuses to
overwrite any existing destination. The three base choices select authoring
scaffolding, rather than a codec allowlist: a copied JSON can describe any
protocol expressible by the current generic primitives.

After editing, update the model and the manifest's author-chosen `request_ids`
paths together. Explicitly regenerate managed fixtures and replays, then check:

```sh
python3 tools/generic_template_catalog.py --refresh-corpus /tmp/my-generic-protocol
```

This replaces generated `fixtures/*/*.wire` and `seeds/*.replay` inside that
package only. Keep independent custom corpora elsewhere. All declared paths
must remain valid from the model initial state before any file is changed;
the command does not infer a protocol session or fabricate responses. Each
asset publishes atomically and the manifest publishes last, so an interrupted
partial update is rejected by the checker. This is not an all-files transaction.

The checker is read-only:

```sh
python3 tools/generic_template_catalog.py --check
python3 tools/generic_template_catalog.py --check-package /tmp/my-generic-protocol
```

`--check` covers bundled assets; `--check-package` covers a managed copied
package. Neither certifies an unrelated `-i` directory. Raw fixture files are
wire bytes; seeds use `LE32(length) || wire`, and response fixture bytes never
appear in seeds. The manifest binds actual file bytes and request state paths.
Managed seed directories contain only the exact declared, non-hidden `.replay`
files; stray raw files, subdirectories, hidden entries, symbolic links, special
files and oversized artifacts are rejected. Fixture directories likewise have
only the declared regular wire files under `requests/` and `responses/`.
Refresh refuses unknown entries before changing files, and stages temporary
data outside seed/fixture directories.

The schema encodes strict object keys, transport/framing branches, uint/bytes
attribute separation, roles, required fixed/derived values and numeric budgets.
Important bounds match the C implementation:

| Quantity | Bound |
| --- | --- |
| Models / fields per grammar | 128 / 256 |
| States / transitions / correlation rules per response | 64 / 256 / 16 |
| Replay records / repeat limit | 64 / 64 |
| Online example and individual frame bytes | 65,507 |
| Standalone wire grammar bytes length/range | 1 MiB |
| Serialized replay and native JSON file | 1 MiB |
| uint width / suggested values | 1..8 bytes / at most32 |
| TCP framing width | 1..4 bytes |

The online schema intentionally requires `online:true`. Five checked-in
industrial migration subsets with `online:false` remain offline inventories;
do not change the flag merely to make them satisfy this schema. Optional
`limitations` and `unsupported` payloads are opaque annotations in the C
loader; this structural schema does not invent executable semantics for them.

JSON Schema is only one layer. The native loader must still check field/message
uniqueness, UTF-8 string byte lengths, numeric/bounds relations, prior-field
length references, `size_of` targets, parsed examples and zero-wire exclusion,
matching ambiguity, framing equations, request budgets, state identities and
correlation types. Native JSON syntax also rejects duplicate keys, floats,
invalid Unicode, more than65,536 nodes or depth beyond96; those are lexical or
semantic checks rather than assertions this schema alone can prove.

All examples use a flat wire struct with fixed magic/opcode, a derived message
length, a mutable HEAD serial, and CONTENT payload. Their declared states are
model states, not StateAFL memory state IDs. Live request/response execution
permits one pending response at a time and uses prepare, commit after complete
submission, and cancel on failure. General conditional arrays, BER, arbitrary
scripts and server-issued session-value binding need language support beyond
these templates.

`tests/generic-wire/test_generic_template_contract.c` calls the real C loader,
sequence validator and response transaction API when run later.
`tests/protocol/test_generic_templates.py` checks schema branches, complete
catalog copies and stale asset rejection. This repair only supplies these
regression sources; test execution and actual target sessions are not claimed.
