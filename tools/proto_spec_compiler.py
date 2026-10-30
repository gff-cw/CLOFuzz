#!/usr/bin/env python3
"""Compile the declarative ICP-IR 1 format. No executable expressions are allowed."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlparse

import yaml
import jsonschema
from native_protocol_codecs import inspect as native_inspect, same_kind as native_same_kind

ROOT = Path(__file__).resolve().parents[1]
CODECS = {"bacnet", "modbus", "iec104", "mms", "enip", "opcua"}
RUNTIME_CODECS = CODECS
RUNTIME_OPS = {"length_of", "count_of", "offset_of", "checksum_of",
               "copy_from_message", "bind_from_response",
               "correlate_request_response", "sequence_number", "tagged_length"}
OPS = {"length_of", "count_of", "offset_of", "checksum_of", "copy_from_message",
       "bind_from_response", "correlate_request_response", "sequence_number",
       "conditional_presence", "tagged_length"}
TYPES = {"uint8": 1, "uint16": 2, "uint24": 3, "uint32": 4, "uint64": 8,
         "bytes": 0, "string": 0, "bacnet_tags": 0, "ber_tlv": 0,
         "epath": 0, "nodeid": 0}
BACNET_RUNTIME_TYPES = {"uint8", "uint16", "uint24", "uint32", "uint64",
                        "bytes", "string", "bacnet_tags"}
RUNTIME_TYPES = set(TYPES)
BACNET_OCTET_LOCATORS = {"bvlc.type", "bvlc.function", "npdu.version", "npdu.control",
                         "apdu.type", "apdu.service", "apdu.invoke", "apdu.max_apdu"}
SCALAR_STRATEGIES = {"enum", "boundary", "bitflip", "arithmetic"}
# These properties document a model; no expression in them is evaluated.
STATIC_METADATA = {
    "protocol": ["name", "version", "scope", "framing", "sources"],
    "message": ["match", "blocks", "notes", "fixture_status", "runtime_encode"],
    "field": ["block", "path", "default", "evidence", "confidence", "structure", "structure_model"],
    "dependency": ["scope", "when"],
    "state": ["states[].meaning", "transitions[].guard", "transitions[].actions", "invalid_strategy"],
}


class SpecError(ValueError):
    pass


class UniqueLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node, deep=False):
    result = {}
    for key, value in node.value:
        name = loader.construct_object(key, deep=deep)
        if not isinstance(name, str) or name in result:
            raise SpecError(f"duplicate or non-string mapping key: {name!r}")
        result[name] = loader.construct_object(value, deep=deep)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def load(path):
    path = Path(path)
    if path.stat().st_size > 2**20:
        raise SpecError(f"{path}: description exceeds 1 MiB")
    try:
        obj = yaml.load(path.read_text(), Loader=UniqueLoader)
        # Reject recursive aliases, non-JSON values and unbounded nesting.
        budget = [0]
        def tree(x, depth=0):
            budget[0] += 1
            if budget[0] > 65536:
                raise SpecError("expanded description exceeds 65536 nodes")
            if depth > 24:
                raise SpecError("description nesting exceeds 24")
            if isinstance(x, dict):
                for v in x.values(): tree(v, depth + 1)
            elif isinstance(x, list):
                for v in x: tree(v, depth + 1)
            elif x is not None and type(x) not in (str, int, bool):
                raise SpecError("only JSON-compatible scalar types are supported")
        tree(obj)
        require(len(json.dumps(obj)) <= 2**20, "expanded description exceeds 1 MiB")
        return obj
    except (yaml.YAMLError, RecursionError) as exc:
        raise SpecError(f"{path}: invalid YAML: {exc}") from exc


def require(condition, message):
    if not condition:
        raise SpecError(message)


def integer(v, lo, hi, where):
    require(type(v) is int and lo <= v <= hi, f"{where}: integer must be in [{lo}, {hi}]")


def ident(s, where):
    require(isinstance(s, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,62}", s),
            f"{where}: invalid identifier {s!r}")


def indexed(items, where):
    result = {}
    for i, item in enumerate(items):
        ident(item["id"], f"{where}[{i}].id")
        require(item["id"] not in result, f"{where}: duplicate ID {item['id']}")
        result[item["id"]] = item
    return result


def structure_tree(node, where, depth=0):
    """Validate static nesting metadata; this is never an executable expression."""
    require(depth <= 16, f"{where}: structure nesting exceeds 16")
    require(node.get("min", 0) <= node.get("max", 65507), f"{where}: reversed structure bounds")
    children = node.get("children", [])
    indexed(children, where + ".children")
    if node["kind"] in {"sequence", "choice", "repeat", "tlv"}:
        require(children, f"{where}: container requires children")
    else:
        require(not children and "type" in node, f"{where}: leaf requires type and no children")
    if node["kind"] == "repeat":
        require("max" in node and node["max"] <= 256, f"{where}: repetition must be bounded")
    for child in children:
        structure_tree(child, where + "." + child["id"], depth + 1)


def validate_example(codec, mid, seed):
    """Envelope consistency, not a claim that every fixture is a valid service."""
    where = f"{mid}.example"
    def size(offset, width, endian, bias=0):
        require(len(seed) >= offset + width and
                int.from_bytes(seed[offset:offset + width], endian) + bias == len(seed),
                f"{where}: inconsistent {codec} length")
    if codec == "bacnet":
        require(len(seed) >= 8 and seed[0] == 0x81 and seed[4] == 1,
                f"{where}: invalid BACnet/IP envelope")
        size(2, 2, "big")
    elif codec == "modbus":
        require(8 <= len(seed) <= 260 and seed[2:4] == b"\0\0", f"{where}: invalid MBAP")
        size(4, 2, "big", 6)
    elif codec == "iec104":
        require(6 <= len(seed) <= 255 and seed[0] == 0x68, f"{where}: invalid APCI")
        size(1, 1, "little", 2)
    elif codec == "mms":
        require(len(seed) >= 7 and seed[:2] == b"\3\0", f"{where}: invalid TPKT")
        size(2, 2, "big")
        require(seed[4] >= 2 and 5 + seed[4] <= len(seed), f"{where}: invalid COTP LI")
    elif codec == "enip":
        require(len(seed) >= 24, f"{where}: truncated encapsulation header")
        size(2, 2, "little", 24)
    elif codec == "opcua":
        require(len(seed) >= 8 and seed[:3] in
                {b"HEL", b"ACK", b"ERR", b"RHE", b"OPN", b"MSG", b"CLO"}
                and seed[3] in b"FCA", f"{where}: invalid UACP/UASC header")
        size(4, 4, "little")


def bacnet_example_fields(seed, where):
    """Resolve runtime locators and validate the actual scoped BACnet fixture.

    Static structure_model strings are deliberately not interpreted here. These
    rules mirror the dedicated BVLC/NPDU/APDU/tag decoder in protocol_runtime.c.
    """
    n = len(seed)
    require(seed[1] in {10, 11}, where + ": unsupported BACnet BVLC function")
    control = seed[5]
    require(not control & 0xd0, where + ": reserved/network-layer NPDU outside runtime scope")
    p = 6
    for bit in (32, 8):
        if control & bit:
            require(p + 3 <= n, where + ": truncated NPDU address")
            length = seed[p + 2]
            require((bit == 32 or length > 0) and p + 3 + length <= n,
                    where + ": invalid NPDU address length")
            p += 3 + length
    if control & 32:
        require(p < n, where + ": missing NPDU hop count")
        p += 1
    require(p < n, where + ": missing APDU")
    kind = seed[p] >> 4
    result = {"bvlc.type": (0, 1), "bvlc.function": (1, 1), "bvlc.length": (2, 2),
              "npdu.version": (4, 1), "npdu.control": (5, 1), "apdu.type": (p, 1)}
    if kind == 0:
        require(n - p >= 4 and not seed[p] & 13, where + ": truncated/segmented confirmed APDU")
        result.update({"apdu.max_apdu": (p + 1, 1), "apdu.invoke": (p + 2, 1), "apdu.service": (p + 3, 1)})
        p += 4
    elif kind == 1:
        require(n - p >= 2 and not seed[p] & 15, where + ": truncated/invalid unconfirmed APDU")
        result["apdu.service"] = (p + 1, 1)
        p += 2
    elif kind in {2, 3, 5, 6, 7}:
        require(n - p >= 3 and (seed[p] & 15) <= (1 if kind == 7 else 0),
                where + ": truncated/segmented response APDU")
        result.update({"apdu.invoke": (p + 1, 1), "apdu.service": (p + 2, 1)})
        p += 3
    else:
        raise SpecError(where + ": unsupported runtime APDU type")
    result["apdu.content"] = (p, n - p)
    tags, stack = [], []
    while p < n:
        header = seed[p]; p += 1
        number, context, lvt = header >> 4, bool(header & 8), header & 7
        if number == 15:
            require(p < n, where + ": truncated extended tag")
            number = seed[p]; p += 1
        opening = context and lvt == 6
        closing = context and lvt == 7
        length = lvt
        if opening or closing:
            length = 0
        elif not context and number == 1:
            require(lvt <= 1, where + ": invalid BOOLEAN tag")
            length = 0
        elif lvt == 5:
            require(p < n, where + ": truncated extended tag length")
            length = seed[p]; p += 1
            if length in {254, 255}:
                width = 2 if length == 254 else 4
                require(p + width <= n, where + ": truncated extended tag length")
                length = int.from_bytes(seed[p:p + width], "big"); p += width
        else:
            require(lvt <= 5, where + ": invalid primitive tag length")
        require(p + length <= n, where + ": truncated tag value")
        if opening:
            require(len(stack) < 24, where + ": tag nesting exceeds 24")
            stack.append(number)
        if closing:
            require(stack and stack.pop() == number, where + ": mismatched closing tag")
        tags.append((number, context, opening or closing, p, length))
        if context and not opening and not closing and number in {0, 1, 2}:
            result.setdefault(("bacnet.object", "bacnet.property", "bacnet.array")[number], (p, length))
        p += length
    require(not stack, where + ": missing closing tag")
    service = seed[result["apdu.service"][0]]
    if (kind, service) in {(1, 8), (0, 12)}:
        expected = 0 if kind == 1 and not tags else 2
        require(len(tags) in ({0, 2} if kind == 1 else {2, 3}), where + ": invalid service tag count")
        for wanted, entry in enumerate(tags):
            number, context, container, offset, length = entry
            require(context and not container and number == wanted and 1 <= length <= 4,
                    where + ": invalid service context tag")
            if kind == 0 and wanted == 0:
                require(length == 4, where + ": object identifier must have four octets")
        if kind == 1 and expected:
            values = [int.from_bytes(seed[o:o + w], "big") for _, _, _, o, w in tags]
            require(0 <= values[0] <= values[1] <= 4194303, where + ": invalid Who-Is limits")
    return result, kind, service


def codec_example_fields(codec, seed, fields, where):
    try:
        return native_inspect(codec, seed, fields)
    except (ValueError, OSError) as exc:
        raise SpecError(f"{where}: runtime codec: {exc}") from exc


def runtime_location(codec, seed, field, locations):
    if codec != "bacnet":
        return locations.get((field["locator"], field["type"], field["width"]))
    if field["locator"].startswith("abs:"):
        offset = int(field["locator"][4:])
        width = field["width"] or len(seed) - offset
        return (offset, width) if offset >= 0 and offset + width <= len(seed) else None
    return locations.get(field["locator"])


def modbus_runtime_repeat(msg, fields, field, where):
    """Permit only the two data-array descriptors executed by the Modbus codec."""
    function = next((f for f in fields.values() if f["locator"] == "abs:7" and
                     f["type"] == "uint8" and f["mutability"] == "fixed"), None)
    code = function["min"] if function and function["min"] == function["max"] else None
    coils = code == 15
    count = next((f for f in fields.values() if f["locator"] == ("abs:12" if coils else "abs:10")
                  and f["type"] == ("uint8" if coils else "uint16")), None)
    expected = {"count": count["id"] if count else "", "min": 1,
                "max": 246 if coils else 123, "element_width": 1 if coils else 2}
    require(msg["direction"] == "request" and code in {15, 16} and count is not None
            and field["locator"] == "abs:13" and field["type"] == "bytes"
            and field["width"] == 0 and field["role"] == "content"
            and field["min"] == (1 if coils else 2) and field["max"] == 246
            and field["repeat"] == expected,
            where + ": generic repeat is static-only; expected exact codec-managed Modbus data/count descriptor")


def runtime_profile_signature(mid, codec, messages, fields, examples):
    """Exclude fixture/default annotations, retain every executed field/dependency.

    Aliases may carry different data examples, but cannot hide different bounds,
    mutation behavior or dependency sources behind the same wire signature.
    """
    msg = messages[mid]
    def field_key(field):
        return tuple(field.get(key) for key in
                     ("locator", "type", "width", "endian", "role", "mutability", "min", "max"))
    def reference_key(other):
        return tuple(name for name, reference in messages.items()
                     if reference["direction"] == messages[other]["direction"]
                     and native_same_kind(codec, examples[other], examples[name])
                     and native_same_kind(codec, examples[name], examples[other]))
    field_signature = []
    for field in fields[mid].values():
        repeat = dict(field.get("repeat", {}))
        if repeat:
            repeat["count"] = fields[mid][repeat["count"]]["locator"]
        field_signature.append((field_key(field), tuple(field["values"]), tuple(sorted(field["strategies"])),
                                tuple(sorted(repeat.items()))))
    dependencies = []
    for dep in msg["dependencies"]:
        source_message = dep.get("message", mid)
        source = dep.get("source", "$message")
        dependencies.append((dep["op"], fields[mid][dep["target"]]["locator"],
                             source if source == "$message" else fields[source_message][source]["locator"],
                             reference_key(source_message), dep.get("unit", 1),
                             dep.get("multiply", 1), dep.get("add", 0), dep.get("algorithm")))
    return msg["direction"], msg["weight"], sorted(field_signature), sorted(dependencies)


def validate(protocol, state):
    for obj, filename in ((protocol, "protocol_spec.schema.json"),
                          (state, "state_transition.schema.json")):
        schema = json.loads((ROOT / "protocols/schema" / filename).read_text())
        try:
            jsonschema.Draft202012Validator(schema).validate(obj)
        except jsonschema.ValidationError as exc:
            raise SpecError(f"{filename}:{'.'.join(map(str, exc.absolute_path))}: {exc.message}") from exc
    require(protocol["protocol_id"] == state["protocol_id"], "protocol/state ID mismatch")
    require(protocol["codec"] in CODECS, f"unsupported encoder: {protocol['codec']}")
    runtime = protocol["support"]["runtime"]
    codec = protocol["codec"]
    require(not runtime or protocol["codec"] in RUNTIME_CODECS,
            f"runtime encoder unavailable for {protocol['codec']}; declare static-only support")
    require(protocol["transport"] == ("udp" if protocol["codec"] == "bacnet" else "tcp"),
            "codec/transport mismatch")
    messages = indexed(protocol["messages"], "messages")
    states = indexed(state["states"], "states")
    require(state["initial"] in states, "initial state does not exist")
    sources = indexed(protocol["sources"], "sources")
    for source in sources.values():
        url = urlparse(source["url"])
        require(url.scheme in {"http", "https"} and url.netloc, "source must have an HTTP(S) URL")
    fields, examples, runtime_locations = {}, {}, {}
    for mid, msg in messages.items():
        require(0 < len(msg["fields"]) <= 64, f"{mid}: expected 1..64 fields")
        integer(msg["weight"], 1, 1000, f"{mid}.weight")
        # C's hex reader accepts pairs only, whereas bytes.fromhex also
        # accepts whitespace. Keep every accepted runtime IR loadable.
        require(re.fullmatch(r"(?:[0-9A-Fa-f]{2})*", msg["example"]),
                f"{mid}: invalid hexadecimal example (use contiguous octet pairs)")
        try:
            seed = bytes.fromhex(msg["example"])
        except ValueError as exc:
            raise SpecError(f"{mid}: invalid hexadecimal example") from exc
        require(0 < len(seed) <= 65507, f"{mid}: invalid example size")
        require(len(seed) + 4 <= state["limits"]["max_bytes"], f"{mid}: example exceeds sequence byte limit")
        validate_example(protocol["codec"], mid, seed)
        examples[mid] = seed
        if runtime:
            require(msg["direction"] != "both", f"{mid}: runtime direction must be request or response")
            require(msg.get("fixture_status", "complete") == "complete",
                    f"{mid}: runtime requires a complete fixture")
            if codec == "bacnet":
                locations, kind, service = bacnet_example_fields(seed, f"{mid}.example")
                # I-Am is an unconfirmed service request on the wire, but models
                # the reply to Who-Is in this request/response campaign vocabulary.
                require((kind in {0, 1} if msg["direction"] == "request"
                         else kind in {2, 3, 5, 6, 7} or (kind, service) == (1, 0)),
                        f"{mid}: example APDU/direction mismatch")
                if msg["direction"] == "request":
                    require((kind, service) in {(1, 8), (0, 12)},
                            f"{mid}: runtime request encoder unavailable for APDU/service")
            else:
                locations = codec_example_fields(codec, seed, msg["fields"], f"{mid}.example")
            runtime_locations[mid] = locations
        if "runtime_encode" in msg:
            require(msg["runtime_encode"] == (runtime and msg["direction"] == "request"),
                    f"{mid}: runtime_encode is a capability assertion, not an execution switch")
        fields[mid] = indexed(msg["fields"], f"{mid}.fields")
        blocks = indexed(msg["blocks"], f"{mid}.blocks")
        for block in blocks.values():
            require("parent" not in block or block["parent"] in blocks, f"{mid}: missing parent block")
        membership = {}
        require("HEAD" in blocks and "CONTENT" in blocks, f"{mid}: HEAD and CONTENT blocks required")
        for block in blocks.values():
            for fid in block["fields"]:
                require(fid in fields[mid], f"{mid}.{block['id']}: missing field {fid}")
                require(fid not in membership, f"{mid}: field {fid} listed in multiple blocks")
                membership[fid] = block["id"]
            if "parent" in block:
                require(block["parent"] in blocks, f"{mid}: missing parent block")
            seen, cur = set(), block
            while "parent" in cur:
                require(cur["id"] not in seen, f"{mid}: block parent cycle")
                seen.add(cur["id"])
                cur = blocks[cur["parent"]]
        for fid, f in fields[mid].items():
            where = f"{mid}.{fid}"
            require(f["type"] in TYPES, f"{where}: unsupported field type")
            integer(f["width"], 0, 65507, where + ".width")
            require(not TYPES[f["type"]] or f["width"] == TYPES[f["type"]], f"{where}: type/width mismatch")
            require(f["endian"] in ("big", "little"), where + ": invalid endian")
            require(f["evidence"] in sources, where + ": missing source")
            require(f["block"] in blocks, where + ": missing block")
            require(membership.get(fid) == f["block"], where + ": block membership mismatch")
            require(f["locator"] and len(f["locator"]) < 64, where + ": invalid locator")
            if runtime:
                require(f["type"] in (BACNET_RUNTIME_TYPES if codec == "bacnet" else RUNTIME_TYPES),
                        where + ": unsupported runtime field type")
                require("when" not in f, where + ": generic when is static-only; codecs handle their scoped conditional structure")
                if "repeat" in f:
                    require(codec == "modbus", where + ": generic repeat is static-only")
                    modbus_runtime_repeat(msg, fields[mid], f, where)
                if codec == "bacnet":
                    require(f["locator"] in {"bvlc.type", "bvlc.function", "bvlc.length", "npdu.version", "npdu.control",
                            "apdu.type", "apdu.service", "apdu.invoke", "apdu.max_apdu", "apdu.content",
                            "bacnet.object", "bacnet.property", "bacnet.array"} or f["locator"].startswith("abs:"),
                            where + ": unsupported runtime locator")
                    if f["locator"] in BACNET_OCTET_LOCATORS:
                        require(f["type"] == "uint8", where + ": BACnet octet locator requires uint8")
                    if f["locator"] == "bvlc.length":
                        require(f["type"] == "uint16", where + ": BVLC length locator requires uint16")
                    if f["locator"] == "bacnet.object":
                        require(f["type"] == "uint32", where + ": BACnet object locator requires uint32")
                    if f["locator"] in {"bacnet.property", "bacnet.array"}:
                        require(f["type"] in {"uint8", "uint16", "uint24", "uint32"},
                                where + ": BACnet unsigned context locator requires uint8..uint32")
                    if f["locator"] == "apdu.content":
                        require(f["width"] == 0, where + ": APDU content locator requires a variable field")
            if f["locator"].startswith("abs:"):
                try: offset = int(f["locator"][4:])
                except ValueError as exc: raise SpecError(where + ": invalid offset") from exc
                require(re.fullmatch(r"[0-9]+", f["locator"][4:]) and 0 <= offset < len(seed)
                        and offset + f["width"] <= len(seed), where + ": locator exceeds example")
            if TYPES[f["type"]]:
                integer(f["min"], 0, 2 ** (8 * f["width"]) - 1, where + ".min")
                integer(f["max"], f["min"], 2 ** (8 * f["width"]) - 1, where + ".max")
                integer(f["default"], f["min"], f["max"], where + ".default")
                for v in f["values"]: integer(v, f["min"], f["max"], where + ".values")
            else:
                require(isinstance(f["default"], str), where + ": variable field default must be string")
                integer(f["min"], 0, 65507, where + ".min")
                integer(f["max"], f["min"], 65507, where + ".max")
                require(f["width"] == 0, where + ": variable field requires width zero")
                require(not f["values"], where + ": variable fields do not support scalar enum values")
                if f["type"] == "string":
                    default_size = len(f["default"].encode("utf-8"))
                else:
                    require(re.fullmatch(r"(?:[0-9A-Fa-f]{2})*", f["default"]),
                            where + ": byte-oriented default must be hexadecimal octet pairs")
                    default_size = len(f["default"]) // 2
                integer(default_size, f["min"], f["max"], where + ".default byte length")
            require((f["role"] == "fixed") == (f["mutability"] == "fixed"),
                    where + ": fixed role and mutability must agree")
            require((f["role"] == "derived") == (f["mutability"] == "derived"),
                    where + ": derived role and mutability must agree")
            if f["mutability"] == "fixed":
                if TYPES[f["type"]]:
                    require(f["min"] == f["max"] == f["default"], where + ": fixed field must have one value and fixed role")
                else:
                    require(not runtime, where + ": fixed variable bytes are static-only; runtime matching requires scalar fixed fields")
                    require(f["min"] == f["max"] == default_size,
                            where + ": fixed variable field bounds must equal default byte length")
            require(set(f["strategies"]) <= {"enum", "boundary", "bitflip", "arithmetic", "afl", "resize"}, where + ": unknown strategy")
            if runtime:
                location = runtime_location(codec, seed, f, locations)
                require(location is not None or f["mutability"] == "conditional",
                        where + ": runtime field absent from example; declare conditional mutability")
                if location is not None:
                    offset, width = location
                    require(not f["width"] or 1 <= width <= 8, where + ": runtime scalar locator has invalid width")
                    actual = int.from_bytes(seed[offset:offset + width], f["endian"]) if f["width"] else width
                    integer(actual, f["min"], f["max"], where + ".example value")
                if f["role"] == "head" and f["mutability"] in {"fuzzable", "conditional"}:
                    require(f["width"] > 0, where + ": runtime HEAD mutation requires an integer field")
                    require(not f["strategies"] or set(f["strategies"]) & SCALAR_STRATEGIES,
                            where + ": runtime HEAD mutation requires a scalar strategy")
                if codec == "bacnet" and msg["direction"] == "request" and f["role"] == "content" and not f["width"] and f["mutability"] in {"fuzzable", "conditional"}:
                    require((kind, service, f["locator"]) == (1, 8, "apdu.content"),
                            where + ": runtime variable CONTENT encoder unavailable")
            if "when" in f:
                require(f["when"]["field"] in fields[mid], where + ": missing conditional field")
                guard = fields[mid][f["when"]["field"]]
                require(TYPES[guard["type"]] > 0, where + ": condition selector must be integer")
                max_guard = 2**(8*guard["width"]) - 1
                integer(f["when"]["mask"], 0, max_guard, where + ".when.mask")
                integer(f["when"]["equals"], 0, max_guard, where + ".when.equals")
                require(f["when"]["equals"] & ~f["when"]["mask"] == 0, where + ": condition value has bits outside mask")
            if "repeat" in f:
                integer(f["repeat"]["max"], 1, 256, where + ".repeat.max")
                integer(f["repeat"].get("min", 0), 0, f["repeat"]["max"], where + ".repeat.min")
                require(f["repeat"]["count"] in fields[mid], where + ": missing count field")
                require(TYPES[fields[mid][f["repeat"]["count"]]["type"]] > 0, where + ": repetition count must be integer")
            if "structure_model" in f:
                structure_tree(f["structure_model"], where + ".structure_model")
    # Typed references and cycles apply equally to local and cross-message edges.
    graph = {}
    for mid, msg in messages.items():
        derived_targets = set()
        for dep in msg["dependencies"]:
            require(dep["op"] in OPS, f"{mid}: unsupported dependency {dep['op']}")
            require(not runtime or dep["op"] in RUNTIME_OPS,
                    f"{mid}: dependency not available in runtime: {dep['op']}")
            require(dep["target"] in fields[mid], f"{mid}: missing dependency target {dep['target']}")
            require(dep["target"] not in derived_targets, f"{mid}: multiple dependency writers for {dep['target']}")
            derived_targets.add(dep["target"])
            require(dep["op"] in {"conditional_presence", "correlate_request_response"}
                    or fields[mid][dep["target"]]["mutability"] != "fixed",
                    f"{mid}: dependency cannot write a fixed field")
            sm = dep.get("message", mid)
            require(sm in messages, f"{mid}: missing source message {sm}")
            sf = dep.get("source", "$message")
            require(sf == "$message" or sf in fields[sm], f"{mid}: missing dependency source {sm}.{sf}")
            if dep["op"] in {"copy_from_message", "bind_from_response", "correlate_request_response"}:
                require(sf != "$message", f"{mid}: copy requires a scalar source")
                a, b = fields[mid][dep["target"]], fields[sm][sf]
                require(a["type"] == b["type"] and a["width"] == b["width"], f"{mid}: incompatible dependency types")
                require(TYPES[a["type"]] > 0, f"{mid}: scalar dependency requires integer fields")
                if dep["op"] == "bind_from_response":
                    require(messages[sm]["direction"] in {"response", "both"}, f"{mid}: response binding requires response source")
                if dep["op"] == "correlate_request_response":
                    require(msg["direction"] in {"response", "both"} and messages[sm]["direction"] in {"request", "both"},
                            f"{mid}: correlation must link response to request")
            if dep["op"] not in {"conditional_presence", "tagged_length"}:
                require(TYPES[fields[mid][dep["target"]]["type"]] > 0,
                        f"{mid}: dependency target must be an integer")
            if dep["op"] in {"length_of", "count_of", "offset_of", "checksum_of", "tagged_length"}:
                require(sm == mid, f"{mid}: structural dependencies require local source")
            if dep["op"] == "checksum_of":
                require(dep.get("algorithm") in {"sum8", "crc32"}, f"{mid}: unsupported checksum algorithm")
            else:
                require("algorithm" not in dep, f"{mid}: algorithm applies only to checksum_of")
            integer(dep.get("unit", 1), 1, 65507, f"{mid}.dependency.unit")
            integer(dep.get("multiply", 1), 1, 65507, f"{mid}.dependency.multiply")
            integer(dep.get("add", 0), -65507, 65507, f"{mid}.dependency.add")
            if runtime:
                if dep["op"] == "tagged_length":
                    target = fields[mid][dep["target"]]
                    require(codec == "mms" and target["type"] == "ber_tlv" and
                            target["width"] == 0 and target["locator"] == "ber:presentation" and
                            sf == "$message" and sm == mid,
                            f"{mid}: tagged_length requires codec-managed MMS presentation and $message source")
                require(dep["op"] in {"length_of", "count_of", "sequence_number"} or dep.get("unit", 1) == 1,
                        f"{mid}: dependency unit is not executed for {dep['op']}")
                require(dep["op"] in {"length_of", "count_of", "offset_of"} or dep.get("add", 0) == 0,
                        f"{mid}: dependency add is not executed for {dep['op']}")
                require(dep["op"] in {"length_of", "count_of"} or dep.get("multiply", 1) == 1,
                        f"{mid}: dependency multiply is not executed for {dep['op']}")
                if dep["op"] == "sequence_number":
                    require(sm == mid and sf in {"$message", dep["target"]},
                            f"{mid}: sequence_number uses its target's own previous value")
            # Message size and codec-managed tag lengths are structural leaves.
            if sf != "$message" and dep["op"] not in {"correlate_request_response", "sequence_number"}:
                graph.setdefault((mid, dep["target"]), []).append((sm, sf))
        for fid, field in fields[mid].items():
            if field["mutability"] in {"derived", "runtime_bound"}:
                require(fid in derived_targets,
                        f"{mid}.{fid}: {field['mutability']} field requires a dependency writer")
                if field["mutability"] == "runtime_bound":
                    writer = next(d for d in msg["dependencies"] if d["target"] == fid)
                    require(writer["op"] in {"copy_from_message", "bind_from_response", "correlate_request_response", "sequence_number"},
                            f"{mid}.{fid}: runtime_bound requires a binding/correlation/sequence dependency")
                else:
                    writer = next(d for d in msg["dependencies"] if d["target"] == fid)
                    require(writer["op"] not in {"conditional_presence", "correlate_request_response"},
                            f"{mid}.{fid}: derived field requires a value-producing dependency")
    if runtime:
        # Mirror C selection: direction, codec service, then every required
        # field's range/fixed constraint. Human-facing match labels never run.
        signatures = {}
        for mid, seed in examples.items():
            matches = []
            for candidate, candidate_fields in fields.items():
                if messages[candidate]["direction"] != messages[mid]["direction"]:
                    continue
                if codec != "bacnet" and not native_same_kind(codec, seed, examples[candidate]):
                    continue
                if codec == "bacnet":
                    candidate_locations = runtime_locations[mid]
                else:
                    try:
                        candidate_locations = native_inspect(codec, seed, candidate_fields.values())
                    except (ValueError, OSError):
                        continue
                matched = True
                for field in candidate_fields.values():
                    if codec == "bacnet" and field["mutability"] != "fixed":
                        continue
                    location = runtime_location(codec, seed, field, candidate_locations)
                    if location is None:
                        if field["mutability"] != "conditional":
                            matched = False
                            break
                        continue
                    offset, width = location
                    actual = int.from_bytes(seed[offset:offset + width], field["endian"]) if field["width"] else width
                    if not field["min"] <= actual <= field["max"]:
                        matched = False
                        break
                if matched:
                    matches.append(candidate)
            equivalent = matches == [mid]
            if codec != "bacnet" and mid in matches:
                for candidate in matches:
                    if candidate not in signatures:
                        signatures[candidate] = runtime_profile_signature(candidate, codec, messages, fields, examples)
                equivalent = all(signatures[candidate] == signatures[mid] for candidate in matches)
            require(equivalent,
                    f"{mid}: ambiguous runtime message matching: {matches}; match is static metadata; only equivalent codec profiles may alias")
    visiting, visited = set(), set()
    for root in graph:
        stack = [(root, False)]
        while stack:
            node, exiting = stack.pop()
            if exiting:
                visiting.remove(node)
                visited.add(node)
            elif node not in visited:
                require(node not in visiting, f"dependency cycle at {node}")
                visiting.add(node)
                stack.append((node, True))
                stack.extend((other, False) for other in reversed(graph.get(node, [])))
    transition_keys = set()
    for tr in state["transitions"]:
        require(tr["from"] in states and tr["to"] in states, "transition references missing state")
        require(tr["message"] in messages, "transition references missing message")
        if tr.get("response"):
            require(tr["response"] in messages, "transition references missing response")
            require(messages[tr["response"]]["direction"] in {"response", "both"}, "transition response has request direction")
            if runtime:
                require(any(edge["from"] == tr["to"] and edge["message"] == tr["response"]
                            for edge in state["transitions"]),
                        "runtime transition response requires an outgoing response edge")
        key = tr["from"], tr["message"]
        require(not runtime or key not in transition_keys,
                "ambiguous runtime state transition; guard is static metadata")
        transition_keys.add(key)
    reached = {state["initial"]}
    for _ in states:
        reached |= {tr["to"] for tr in state["transitions"] if tr["from"] in reached}
    require(reached == set(states), "unreachable semantic state")
    return protocol, state


def serialize_ir(document):
    """Enforce the C tokenizer's limits on the exact JSON we will publish."""
    def tokens(value, depth=0):
        require(depth <= 24, "serialized IR nesting exceeds runtime depth 24")
        if isinstance(value, dict):
            return 1 + sum(1 + tokens(child, depth + 1) for child in value.values())
        if isinstance(value, list):
            return 1 + sum(tokens(child, depth + 1) for child in value)
        return 1
    require(tokens(document) < 65536, "serialized IR exceeds runtime JSON token budget")
    serialized = json.dumps(document, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    require(len(serialized.encode("utf-8")) <= 2**20,
            "serialized IR exceeds runtime 1 MiB limit")
    return serialized


def compile_spec(protocol, state, output):
    validate(protocol, state)
    output = Path(output)
    p, s = copy.deepcopy(protocol), copy.deepcopy(state)
    p["ir_version"] = s["ir_version"] = 1
    raw_p = serialize_ir(p)
    raw_s = serialize_ir(s)
    bundle_digest = hashlib.sha256((raw_p + raw_s).encode("utf-8")).hexdigest()
    p["bundle_digest"] = s["bundle_digest"] = bundle_digest
    documents = {"protocol_ir.json": serialize_ir(p), "state_ir.json": serialize_ir(s)}
    output.mkdir(parents=True, exist_ok=True)
    for filename, serialized in documents.items():
        tmp_target = output / f".{filename}.tmp.{os.getpid()}"
        tmp_target.write_text(serialized, encoding="utf-8")
        tmp_target.replace(output / filename)
    bundle_manifest = {
        "bundle_version": 1,
        "protocol_id": p.get("protocol_id"),
        "bundle_digest": bundle_digest,
        "files": ["protocol_ir.json", "state_ir.json"]
    }
    tmp_bundle = output / f".spec_bundle.json.tmp.{os.getpid()}"
    tmp_bundle.write_text(json.dumps(bundle_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp_bundle.replace(output / "spec_bundle.json")
    aliases = {}
    if p["support"]["runtime"] and p["codec"] != "bacnet":
        messages = {m["id"]: m for m in p["messages"]}
        fields = {mid: {f["id"]: f for f in m["fields"]} for mid, m in messages.items()}
        examples = {mid: bytes.fromhex(m["example"]) for mid, m in messages.items()}
        signatures = {mid: runtime_profile_signature(mid, p["codec"], messages, fields, examples)
                      for mid in messages}
        for mid in messages:
            for earlier in messages:
                if earlier == mid:
                    break
                if signatures[mid] == signatures[earlier] and native_same_kind(
                        p["codec"], examples[mid], examples[earlier]) and native_same_kind(
                        p["codec"], examples[earlier], examples[mid]):
                    aliases[mid] = aliases.get(earlier, earlier)
                    break
    result = {"protocol": p["protocol_id"], "messages": len(p["messages"]),
              "fields": sum(len(m["fields"]) for m in p["messages"]),
              "semantic_states": len(s["states"]), "validated": True,
              "runtime": p["support"]["runtime"], "scope": p["scope"],
              "example_validation": ("protocol envelope and length consistency; bounded runtime codec validates complete fixtures and exact field ranges; not live service conformance"),
              "message_aliases": aliases,
              "execution_contract": {
                  "static_only": not p["support"]["runtime"],
                  "static_metadata": STATIC_METADATA,
                  "field_when_repeat": "generic when/repeat are static-only; exact Modbus multiwrite data/count repeat descriptors are codec-managed",
                  "dependencies": "whitelisted operations only; scope and when are annotations",
                  "content_scalar_strategies": "runtime uses AFL field projection; values/strategies are annotations for CONTENT scalars",
                  "runtime_encode": "capability assertion derived from runtime support and message direction; never an execution switch",
                  "validator_build": "non-BACnet runtime validation requires a C11 compiler (CC or cc), protocol_codecs.h and all five protocol_codec_*.c sources; no Python in StateAFL mutation loop",
              }}
    (output / "validation.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--protocol", required=True, type=Path)
    ap.add_argument("--state", required=True, type=Path)
    ap.add_argument("--output-dir", required=True, type=Path)
    args = ap.parse_args()
    try:
        print(json.dumps(compile_spec(load(args.protocol), load(args.state), args.output_dir)))
        return 0
    except (SpecError, OSError, KeyError, TypeError, ValueError) as exc:
        print(f"protocol specification error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
