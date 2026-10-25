# BACnet/IP description package

Base profile: `bacnet_ip`. Protocol ID: `local_bacnet_template`.

Scope: BVLC Original-Unicast-NPDU; routed NPDU address parsing; unsegmented Who-Is with optional limits and ReadProperty with optional array index; application/context tag walking and invoke correlation.

Runtime encoder available: true. This flag does not claim this copied package has passed a live target test.

Edit protocol_spec.yaml and state_transition.yaml, then run:

```bash
python3 /path/to/stateafl/tools/proto_spec_compiler.py --protocol protocol_spec.yaml --state state_transition.yaml --output-dir .
```

For a runtime-enabled package, load protocol_ir.json and state_ir.json using afl-fuzz --protocol-spec and --state-spec.
