#!/usr/bin/env python3
"""Check the six fixture subsets against generic-wire C schema constraints.

Independent of the generator and old protocol compiler/codecs. Package identity,
source inventories, fixture correlation and online scope are additional profile
policy checks, not a claim of full protocol conformance or C runtime execution.
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "protocols"
NAMES = ("bacnet_ip", "iec60870_5_104", "iec61850_mms_tcp",
         "modbus_tcp", "ethernet_ip_cip_tcp", "opcua_tcp")
MAX_WIRE = 1048576
MAX_FRAME = 65507


def need(ok, what):
    if not ok:
        raise ValueError(what)


def keys(obj, required, optional=()):
    need(type(obj) is dict and set(required) <= obj.keys() and
         obj.keys() <= set(required) | set(optional), "missing or unknown object keys")


def integer(number, lo=0, hi=(1 << 64)-1):
    need(type(number) is int and lo <= number <= hi, "integer out of bounds")
    return number


def text(s):
    need(type(s) is str and "\0" not in s and len(s.encode("utf-8")) < 64,
         "invalid or oversized string")
    return s


def unhex(s, limit=MAX_WIRE, example=False):
    need(type(s) is str and len(s) % 2 == 0 and len(s)//2 <= limit and
         re.fullmatch("[0-9a-f]+" if example else "[0-9a-fA-F]*", s) is not None,
         "invalid hex")
    return bytes.fromhex(s)


def unique_object(pairs):
    obj = {}
    for key, item in pairs:
        need(key not in obj, "duplicate JSON key: " + key)
        obj[key] = item
    return obj


def load(path):
    raw = path.read_bytes()
    need(len(raw) <= MAX_WIRE, "JSON file exceeds C input budget")
    return json.loads(raw, object_pairs_hook=unique_object)


def value(wire, offset, width, order):
    need(offset + width <= len(wire), "truncated uint")
    return int.from_bytes(wire[offset:offset+width], order)


def parse_grammar(grammar, wire):
    """Validate ordered leaves as gw_compile/gw_parse do; return values/sizes.

    Enum 'values' are mutation choices in C, not a parse-time membership rule.
    An expected value constrains even non-fixed leaves. Derived targets may be
    the entire message or any named leaf, including a later field. Byte length
    references still require a prior uint and apply their signed add once.
    """
    keys(grammar, ("kind", "fields"))
    need(grammar["kind"] == "struct", "grammar must be struct")
    fields = grammar["fields"]
    need(type(fields) is list and 1 <= len(fields) <= 256, "invalid field array")
    need(len(wire) <= MAX_WIRE, "wire exceeds C budget")
    offset, ids, sizes, derived = 0, {}, {}, []
    for index, f in enumerate(fields):
        keys(f, ("id", "kind", "role"), ("width", "byte_order", "length", "min", "max",
             "expected", "expected_hex", "values", "derived"))
        fid = text(f["id"])
        need(re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", fid) is not None and fid not in ids,
             "invalid or duplicate field ID")
        kind, role = f["kind"], f["role"]
        need(role in ("fixed", "derived", "head", "content"), "invalid role")
        need(kind in ("uint", "bytes"), "invalid kind")
        if kind == "uint":
            need(not {"length", "expected_hex"} & f.keys(), "uint with bytes attributes")
            width = integer(f["width"], 1, 8)
            need(f["byte_order"] in ("big", "little"), "invalid byte_order")
            ceiling = (1 << (8 * width))-1
            low, high = integer(f.get("min", 0)), integer(f.get("max", ceiling), 0, ceiling)
            need(low <= high, "invalid bounds")
            got = value(wire, offset, width, f["byte_order"])
            if role == "fixed":
                need("expected" in f, "fixed uint needs expected")
            if "expected" in f:
                expected = integer(f["expected"], low, high)
                need(got == expected, "expected uint mismatch")
            if "values" in f:
                need(type(f["values"]) is list and len(f["values"]) <= 32, "invalid enum count")
                for choice in f["values"]:
                    integer(choice, low, high)
            if role == "derived":
                rule = f["derived"]
                keys(rule, ("op", "target"), ("add",))
                target = text(rule["target"])
                need(rule["op"] == "size_of", "size_of rule required")
                add = integer(rule.get("add", 0), -(1 << 63), (1 << 63)-1)
                derived.append((got, target, add))
            else:
                need("derived" not in f, "unexpected derived rule")
        else:
            need(not {"width", "byte_order", "values", "expected", "derived"} & f.keys(),
                 "bytes with uint attributes")
            need(role in ("fixed", "content"), "unsupported bytes role")
            low, high = integer(f.get("min", 0)), integer(f.get("max", MAX_WIRE), 0, MAX_WIRE)
            need(low <= high, "invalid bounds")
            length = f["length"]
            if type(length) is dict:
                keys(length, ("ref",), ("add",))
                ref = text(length["ref"])
                need(ref in ids and ids[ref][0] == "uint", "length ref must name prior uint")
                add = integer(length.get("add", 0), -(1 << 63), (1 << 63)-1)
                width = integer(ids[ref][1] + add, 0, MAX_WIRE)
            elif length == "rest":
                need(index+1 == len(fields), "rest must be final")
                width = len(wire)-offset
            else:
                width = integer(length, 0, MAX_WIRE)
                need(low <= width <= high, "constant length outside bounds")
            need(offset+width <= len(wire), "truncated bytes")
            got = wire[offset:offset+width]
            if role == "fixed":
                need("expected_hex" in f, "fixed bytes need expected_hex")
            if "expected_hex" in f:
                expected = unhex(f["expected_hex"])
                need(low <= len(expected) <= high and got == expected, "expected bytes mismatch")
        observed = got if kind == "uint" else width
        need(low <= observed <= high, "value outside bounds")
        ids[fid], sizes[fid] = (kind, got), width
        offset += width
    need(offset == len(wire), "unconsumed wire tail")
    for got, target, add in derived:
        need(target == "$message" or target in sizes, "unknown size_of target")
        expected = (len(wire) if target == "$message" else sizes[target]) + add
        integer(expected)
        need(got == expected, "derived value mismatch")
    return ids


def check(path):
    name = path.parent.name
    try:
        return check_profile(path, name)
    except (ValueError, KeyError, TypeError) as error:
        raise ValueError(f"{name}: {error}") from error


def check_profile(path, name):
    data = load(path)
    keys(data, ("format", "version", "protocol_id", "transport", "online", "framing",
                "messages", "states", "limits"), ("unsupported", "limitations"))
    need(name in NAMES and text(data["protocol_id"]) == name, "protocol ID")
    need(data["format"] == "stateafl.generic-wire" and integer(data["version"], 1, 1) == 1,
         "format/version")
    need(data["transport"] in ("tcp", "udp"), "transport")
    need(type(data["online"]) is bool and data["online"] is (name == "modbus_tcp"), "online scope")
    framing = data["framing"]
    if data["transport"] == "udp":
        keys(framing, ("kind",))
        need(framing["kind"] == "datagram", "UDP framing")
    else:
        keys(framing, ("kind", "offset", "width", "byte_order", "add"))
        need(framing["kind"] == "length_field", "TCP framing")
        integer(framing["offset"], 0, MAX_FRAME)
        integer(framing["width"], 1, 4)
        need(framing["offset"]+framing["width"] <= MAX_FRAME and
             framing["byte_order"] in ("big", "little"), "TCP framing bounds/order")
        integer(framing["add"], -(1 << 63), (1 << 63)-1)
    lim = data["limits"]
    keys(lim, ("max_messages", "max_repeat", "max_bytes"))
    integer(lim["max_messages"], 1, 64)
    integer(lim["max_repeat"], 1, 64)
    integer(lim["max_bytes"], 8, MAX_WIRE)
    original = load(path.parent/"protocol_ir.json")
    need(data["transport"] == original["transport"], "source transport changed")
    examples = {m["id"]: m for m in original["messages"]}
    need(len(examples) == len(original["messages"]), "duplicate source message ID")
    messages = data["messages"]
    need(type(messages) is list and 1 <= len(messages) <= 128, "invalid message array")
    seen, parsed = {}, {}
    for m in messages:
        keys(m, ("id", "direction", "weight", "example_hex", "grammar"), ("correlate",))
        mid = text(m["id"])
        need(mid and mid in examples and mid not in seen, "invalid or duplicate message ID")
        need(m["direction"] in ("request", "response") and
             m["direction"] == examples[mid]["direction"] and m["weight"] == examples[mid]["weight"],
             f"{mid}: source direction/weight changed")
        integer(m["weight"], 1, 1000)
        wire = unhex(m["example_hex"], MAX_FRAME, example=True)
        need(wire == bytes.fromhex(examples[mid]["example"]), f"{mid}: fixture changed")
        try:
            parsed[mid] = parse_grammar(m["grammar"], wire)
        except (ValueError, KeyError, TypeError) as error:
            raise ValueError(f"{mid}: {error}") from error
        if framing["kind"] == "length_field":
            need(value(wire, framing["offset"], framing["width"], framing["byte_order"])+
                 framing["add"] == len(wire), f"{mid}: framing length")
        seen[mid] = m
    request = sum(m["direction"] == "request" for m in messages)
    response = len(messages)-request
    need(request > 0 and response > 0, "request+response required")
    for m in messages:
        if "correlate" not in m:
            continue
        corr = m["correlate"]
        need(m["direction"] == "response" and type(corr) is list and len(corr) <= 16,
             "invalid correlations")
        for c in corr:
            keys(c, ("field", "request", "source"))
            field, req, source = (text(c[k]) for k in ("field", "request", "source"))
            need(field in parsed[m["id"]] and parsed[m["id"]][field][0] == "uint" and
                 req in seen and seen[req]["direction"] == "request" and
                 source in parsed[req] and parsed[req][source][0] == "uint", "correlation reference")
            need(parsed[m["id"]][field][1] == parsed[req][source][1], "example correlation mismatch")
    missing = set(examples)-seen.keys()
    unsupported = data["unsupported"]
    need(type(unsupported) is list, "unsupported inventory")
    recorded = set()
    for entry in unsupported:
        keys(entry, ("message", "reason"))
        need(type(entry["message"]) is str and entry["message"] not in recorded and
             type(entry["reason"]) is str and entry["reason"].strip(), "unsupported entry")
        recorded.add(entry["message"])
    need(missing == recorded, "unsupported inventory")
    need(type(data["limitations"]) is list and data["limitations"] and
         all(type(s) is str and s.strip() for s in data["limitations"]), "limitations required")
    states = data["states"]
    keys(states, ("initial", "transitions"))
    initial = text(states["initial"])
    transitions = states["transitions"]
    need(type(transitions) is list and 1 <= len(transitions) <= 256, "invalid transitions")
    state_names, edges = set(), set()
    for t in transitions:
        keys(t, ("from", "to", "message"), ("response",))
        origin, target, mid = (text(t[k]) for k in ("from", "to", "message"))
        need(mid in seen and seen[mid]["direction"] == "request", "transition request")
        if "response" in t:
            rid = text(t["response"])
            need(rid in seen and seen[rid]["direction"] == "response", "transition response")
        need((origin, mid) not in edges, "ambiguous transition")
        edges.add((origin, mid))
        state_names.update((origin, target))
    need(initial in state_names and len(state_names) <= 64, "initial state or state count")
    return {"protocol": name, "online": data["online"], "requests": request,
            "responses": response, "unsupported": len(missing)}


if __name__ == "__main__":
    results = [check(ROOT/name/"generic_wire.json") for name in NAMES]
    print(json.dumps(results, indent=2))
