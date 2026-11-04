# udp_oneway generic-wire v1 example

This fictional, editable JSON package is a complete input shape for the online generic C loader. No protocol-specific codec, old YAML or Python execution is used by the online mutator. It is not an industrial protocol profile and has not been run against a target in this repair.

Wire layout: `magic:u8 | body_length:u16 big | opcode:u8 | serial:u16 big | payload:bytes`. Body length is `message bytes - 3`; payload length is `body_length - 3`. The request opcode is 1; no response is expected. Magic is 167. Each UDP datagram is one complete wire message.

- `generic_wire.json`: authoritative example description; edit actual wire, fields, limits and state/response rules together.
- `fixtures/requests/*.wire`: wire bytes without a replay prefix.
- `fixtures/responses/*.wire`: expected response examples only; none are sent in seeds.
- `seeds/*.replay`: request-only `LE32(length) || wire`, one request and two repeats.
- `seed_manifest.json`: exact description/fixture/seed hashes and projected request states; file consistency is not runtime acceptance.

Load through `afl-fuzz --generic-spec /path/to/this/generic_wire.json`, with `-i /path/to/this/seeds`, a fresh output directory and `-N udp://127.0.0.1/PORT`. A compatible controlled target and its command are required. For response-bearing packages it must send a complete matching response before the next request. No response bytes, session IDs or tracer states are fabricated by this package. Target-side application boundary markers remain a separate requirement for nonzero memory-state M2 selection.

After editing, update manifest request_ids if the request path changed, then explicitly run `python3 tools/generic_template_catalog.py --refresh-corpus /path/to/this` and read-only `--check-package /path/to/this`. Refresh replaces this package’s managed fixtures and seeds; keep custom corpora elsewhere. JSON Schema is a structural check; actual grammar parsing, framing equations, references, zero-wire rejection, correlation and state validity remain checked by the native C loader.
