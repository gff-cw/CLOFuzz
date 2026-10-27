#!/usr/bin/env python3
"""Build bounded generic-wire descriptions; mutation itself runs in C."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "protocols"
CHOICES = {
    "modbus_tcp": ("read_holding", "read_response"),
    "iec60870_5_104": ("start_act", "start_con", "interrogation", "interrogation_confirmation"),
    "bacnet_ip": ("read_property", "read_property_ack"),
    "iec61850_mms_tcp": ("cotp_cr", "cotp_cc"),
    "ethernet_ip_cip_tcp": ("register", "register_response"),
    "opcua_tcp": ("hello", "ack"),
}
FRAMING = {
    "modbus_tcp": (4, 2, "big", 6),
    "iec60870_5_104": (1, 1, "big", 2),
    "iec61850_mms_tcp": (2, 2, "big", 0),
    "ethernet_ip_cip_tcp": (2, 2, "little", 24),
    "opcua_tcp": (4, 4, "little", 0),
}
STATES = {
    "modbus_tcp": ("ready", [("ready", "read_holding", "ready", "read_response")]),
    "iec60870_5_104": ("stopped", [("stopped", "start_act", "started", "start_con"),
                                  ("started", "interrogation", "started", "interrogation_confirmation")]),
    "bacnet_ip": ("ready", [("ready", "read_property", "ready", "read_property_ack")]),
    "iec61850_mms_tcp": ("disconnected", [("disconnected", "cotp_cr", "transport_connected", "cotp_cc")]),
    "ethernet_ip_cip_tcp": ("unregistered", [("unregistered", "register", "registered", "register_response")]),
    "opcua_tcp": ("disconnected", [("disconnected", "hello", "acknowledged", "ack")]),
}
CORRELATE = {
    ("modbus_tcp", "read_response"): (("transaction", "read_holding", "transaction"),
                                     ("unit", "read_holding", "unit")),
    ("bacnet_ip", "read_property_ack"): (("invoke_id", "read_property", "invoke_id"),),
    ("ethernet_ip_cip_tcp", "register_response"): (("context", "register", "context"),),
}
LIMITS = {
    "modbus_tcp": "Only FC03 one-register request/response; exceptions, other functions and concurrent transactions are absent.",
    "iec60870_5_104": "Fixed STARTDT and interrogation examples only; I/S sequence/window and full ASDU rules absent.",
    "bacnet_ip": "Fixed un-routed, unsegmented ReadProperty and one exact ACK only; LVT, optional NPDU and other values absent.",
    "iec61850_mms_tcp": "TPKT/COTP CR/CC only, no MMS service; session, presentation, ACSE and BER rules absent.",
    "ethernet_ip_cip_tcp": "RegisterSession pair only; session binding, CPF, CIP EPATH and ForwardOpen absent.",
    "opcua_tcp": "Fixed endpoint HEL/ACK only; dynamic UA Binary, services, chunks and token binding absent.",
}

def raw_field(name, wire, offset, length):
    chunk = wire[offset:offset + length]
    return {"id": name, "kind": "bytes", "length": length, "role": "fixed", "expected_hex": chunk.hex()}

def grammar(name, message):
    wire = bytes.fromhex(message["example"])
    specs = []
    for source in message["fields"]:
        locator = source["locator"]
        if locator.startswith("abs:") and locator[4:].isdigit():
            offset = int(locator[4:])
        elif name == "bacnet_ip" and source["id"] == "invoke_id":
            offset = 8 if message["direction"] == "request" else 7
        elif name == "bacnet_ip" and source["id"] == "object_id":
            offset = 11 if message["direction"] == "request" else 10
        elif name == "bacnet_ip" and source["id"] == "property_id":
            offset = 16 if message["direction"] == "request" else 15
        elif name == "bacnet_ip" and source["id"] == "bvlc_length":
            offset = 2
        elif name == "iec61850_mms_tcp" and source["id"] == "tpkt_length":
            offset = 2
        elif name == "ethernet_ip_cip_tcp" and source["id"] == "context":
            offset = 12
        elif name == "ethernet_ip_cip_tcp" and source["id"] == "session":
            offset = 4
        elif name == "opcua_tcp" and source["id"] == "message_size":
            offset = 4
        elif name == "iec61850_mms_tcp" and source["id"] == "cotp_li":
            offset = 4
        elif name == "iec60870_5_104" and source["id"] == "length":
            offset = 1
        elif name == "modbus_tcp" and source["id"] == "length":
            offset = 4
        elif name == "ethernet_ip_cip_tcp" and source["id"] == "length":
            offset = 2
        else:
            continue
        width = source["width"]
        if width and source["type"].startswith("uint"):
            specs.append((offset, width, source))
    # Complex containers, optional branches and overlapping declarative views
    # are represented as exact fixture bytes until a real grammar primitive exists.
    if name == "opcua_tcp":
        specs = [x for x in specs if x[2]["id"] in ("message_size", "protocol_version", "receive_buffer",
                   "send_buffer", "max_message_size", "max_chunk_count")]
    if name == "bacnet_ip":
        specs = [x for x in specs if x[2]["id"] in ("bvlc_length", "invoke_id", "object_id", "property_id")]
    if name == "iec61850_mms_tcp":
        specs = [x for x in specs if x[2]["id"] in ("tpkt_length", "cotp_li", "destination_reference", "source_reference")]
    fields, cursor = [], 0
    for offset, width, source in sorted(specs, key=lambda x: x[0]):
        if offset < cursor or offset + width > len(wire):
            raise ValueError(f"{name}:{message['id']}:{source['id']}: overlapping or truncated field")
        if offset > cursor:
            fields.append(raw_field("fixed_" + str(cursor), wire, cursor, offset-cursor))
        role = source["role"]
        if role not in ("head", "content", "fixed", "derived") or source["mutability"] in ("conditional", "runtime_bound"):
            role = "fixed"
        if name == "modbus_tcp" and source["id"] in ("transaction", "unit") and message["direction"] == "response":
            role = "content"
        if name == "bacnet_ip" and source["id"] == "invoke_id" and message["direction"] == "response":
            role = "content"
        if name == "ethernet_ip_cip_tcp" and source["id"] in ("session", "context") and message["direction"] == "response":
            role = "content"
        if name == "iec60870_5_104" and source["id"] in ("send_seq", "receive_seq", "cot"):
            # The current v1 grammar has no shifted sequence counters or COT bit semantics.
            role = "fixed"
        if name == "opcua_tcp" and source["id"] in ("protocol_version", "receive_buffer", "send_buffer", "max_message_size", "max_chunk_count") and message["direction"] == "response":
            role = "content"
        order = source["endian"]
        value = int.from_bytes(wire[offset:offset + width], order)
        field = {"id": source["id"], "kind": "uint", "width": width,
                 "byte_order": order, "role": role, "min": source["min"], "max": source["max"]}
        if role == "fixed":
            field["min"] = field["max"] = field["expected"] = value
        if role == "derived":
            add = value - len(wire)
            field["derived"] = {"op": "size_of", "target": "$message", "add": add}
        if name == "modbus_tcp" and source["id"] == "byte_count":
            # Executable v1 supports a fixed two-byte FC03 response only;
            # expressing byte_count as total-length-minus-nine would allow
            # arbitrary even/odd lengths without register-count semantics.
            field.pop("derived", None)
            field.update(role="fixed", min=value, max=value, expected=value)
        if name == "modbus_tcp" and source["id"] == "quantity" and message["id"] == "read_holding":
            # FC03 response grammar below has one register (two data bytes).
            # Without count*2 and an arbitrary-register response grammar,
            # mutating quantity would create a valid request whose valid
            # response our online parser would reject.
            field.update(role="fixed", min=value, max=value, expected=value)
        fields.append(field)
        cursor = offset + width
    if name == "modbus_tcp" and message["id"] == "read_response" and cursor == 9:
        # FC03 quantity is fixed to one register; the two response data bytes
        # are arbitrary register contents, not the fixture's literal 0x0001.
        if len(wire) != 11:
            raise ValueError("modbus_tcp: one-register FC03 fixture must be 11 bytes")
        fields.append({"id":"data","kind":"bytes","length":2,
                       "role":"content","min":2,"max":2})
        cursor = len(wire)
    if cursor < len(wire):
        fields.append(raw_field("fixed_" + str(cursor), wire, cursor, len(wire)-cursor))
    return {"kind": "struct", "fields": fields}

def build(name):
    """Return a description without modifying the checked-in artifacts."""
    original = json.loads((ROOT/name/"protocol_ir.json").read_text(encoding="utf-8"))
    kept = set(CHOICES[name])
    source_ids = [m["id"] for m in original["messages"]]
    if len(source_ids) != len(set(source_ids)) or not kept <= set(source_ids):
        raise ValueError(f"{name}: duplicate source IDs or missing selected messages")
    messages = []
    for source in original["messages"]:
        if source["id"] not in kept:
            continue
        message = {"id": source["id"], "direction": source["direction"],
                   "weight": source["weight"], "example_hex": source["example"],
                   "grammar": grammar(name, source)}
        corr = CORRELATE.get((name, source["id"]))
        if corr:
            message["correlate"] = [{"field": f, "request": r, "source": s} for f,r,s in corr]
        messages.append(message)
    # The response correlation keys must be actual uint leaves, not fixture-only bytes.
    for message in messages:
        for item in message.get("correlate", []):
            response_fields = {f["id"] for f in message["grammar"]["fields"] if f["kind"] == "uint"}
            req = next(x for x in messages if x["id"] == item["request"])
            request_fields = {f["id"] for f in req["grammar"]["fields"] if f["kind"] == "uint"}
            if (message["direction"] != "response" or req["direction"] != "request" or
                    item["field"] not in response_fields or item["source"] not in request_fields):
                raise ValueError(f"{name}:{message['id']}: correlation must name request/response uint leaves")
    initial, transitions = STATES[name]
    framing = ({"kind":"datagram"} if original["transport"] == "udp" else
               dict(zip(("offset", "width", "byte_order", "add"), FRAMING[name]), kind="length_field"))
    result = {"format":"stateafl.generic-wire", "version":1,
              "protocol_id":name, "transport":original["transport"], "framing":framing,
              "online":name == "modbus_tcp", "messages":messages,
              "limits":{"max_messages":32,"max_repeat":4,"max_bytes":1048576},
              "states":{"initial":initial, "transitions":[dict(zip(("from", "message", "to", "response"), row))
                                                       for row in transitions]},
              "unsupported":[{"message":m["id"], "reason":"Needs grammar or state rule absent from generic-wire v1."}
                             for m in original["messages"] if m["id"] not in kept],
              "limitations":[LIMITS[name]]}
    return result

def render(name):
    return (json.dumps(build(name), indent=2, ensure_ascii=False)+"\n").encode("utf-8")

def generate(name):
    path = ROOT/name/"generic_wire.json"
    path.write_bytes(render(name))
    print(path)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="check byte-for-byte reproducibility without writing files")
    args = parser.parse_args()
    stale = []
    for name in CHOICES:
        if args.check:
            path = ROOT/name/"generic_wire.json"
            if not path.exists() or path.read_bytes() != render(name):
                stale.append(str(path))
        else:
            generate(name)
    if args.check:
        if stale:
            parser.exit(1, "Missing or stale generic-wire descriptions:\n" + "\n".join(stale) + "\n")
        print("PASS: six generic-wire descriptions reproduce byte-for-byte")
