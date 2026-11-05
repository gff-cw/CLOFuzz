# BACnet/IP reviewed runtime profile

Seven complete fixtures cover Who-Is/I-Am and ReadProperty request/ACK/Error/Reject/server-Abort. The description uses semantic locators for all response fields. NPDU destination/source routing addresses and hop count are decoded before locating the APDU. Application parameter widths and context property/index widths are decoded from BACnet tags rather than fixture offsets.

ReadProperty property/index fields have UInt32 capacity and 1–4-byte wire representations. CONTENT mutation reencodes these values and repairs BVLC length. ACKs must echo the pending invoke, object, property and optional array index; both absent indexes match, a one-sided absence fails. The value locator returns the bytes inside the balanced context-3 container. Nested value tags cannot masquerade as the array index.

`tests/protocol/test_bacnet_dynamic.c` exercises controlled in-process C APIs with routed responses, varying tag widths, scalar growth and response correlation. It uses no external devices. This profile does not replace the published `protocols/bacnet_ip` package, and controlled tests are not BACnet conformance certification.

The runtime remains single-flight and unsegmented. Other services, BACnet/SC, BBMD/foreign-device lifecycle, concurrent invoke tables and arbitrary property-value interpretation are outside scope. `structure_model`, guards and actions remain annotations. The existing generic-wire profile remains separate and offline.

Sources remain the YAML's BACnet Stack 1.5.0 references; paid ASHRAE text was not consulted. See `constraints.json` for remaining boundaries.
