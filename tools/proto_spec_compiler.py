#!/usr/bin/env python3
"""Compile the declarative ICP-IR 1 format. No executable expressions are allowed."""
import argparse
import copy
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlparse

import yaml
import jsonschema

ROOT = Path(__file__).resolve().parents[1]
CODECS = {"bacnet", "modbus", "iec104", "mms", "enip", "opcua"}
RUNTIME_CODECS = {"bacnet"}
RUNTIME_OPS = {"length_of", "count_of", "offset_of", "checksum_of",
               "copy_from_message", "bind_from_response",
               "correlate_request_response", "sequence_number"}
OPS = {"length_of", "count_of", "offset_of", "checksum_of", "copy_from_message",
       "bind_from_response", "correlate_request_response", "sequence_number",
       "conditional_presence", "tagged_length"}
TYPES = {"uint8": 1, "uint16": 2, "uint24": 3, "uint32": 4, "uint64": 8,
         "bytes": 0, "string": 0, "bacnet_tags": 0, "ber_tlv": 0,
         "epath": 0, "nodeid": 0}


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
    fields = {}
    for mid, msg in messages.items():
        require(0 < len(msg["fields"]) <= 64, f"{mid}: expected 1..64 fields")
        integer(msg["weight"], 1, 1000, f"{mid}.weight")
        try:
            seed = bytes.fromhex(msg["example"])
        except ValueError as exc:
            raise SpecError(f"{mid}: invalid hexadecimal example") from exc
        require(0 < len(seed) <= 65507, f"{mid}: invalid example size")
        require(len(seed) + 4 <= state["limits"]["max_bytes"], f"{mid}: example exceeds sequence byte limit")
        validate_example(protocol["codec"], mid, seed)
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
                require(f["locator"] in {"bvlc.type", "bvlc.function", "bvlc.length", "npdu.version", "npdu.control",
                        "apdu.type", "apdu.service", "apdu.invoke", "apdu.max_apdu", "apdu.content",
                        "bacnet.object", "bacnet.property", "bacnet.array"} or f["locator"].startswith("abs:"),
                        where + ": unsupported runtime locator")
                require("when" not in f and "repeat" not in f, where + ": generic when/repeat is static-only; BACnet codec handles conditional tags")
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
                require(not runtime or f["max"] <= 2**63-1,
                        where + ": C runtime IR integers must fit signed 64-bit")
            else:
                require(isinstance(f["default"], str), where + ": variable field default must be string")
                integer(f["min"], 0, 65507, where + ".min")
                integer(f["max"], f["min"], 65507, where + ".max")
                require(f["width"] == 0, where + ": variable field requires width zero")
                require(not f["values"], where + ": variable fields do not support scalar enum values")
            if f["mutability"] == "fixed":
                require(f["role"] == "fixed" and f["min"] == f["max"] == f["default"], where + ": fixed field must have one value and fixed role")
            if f["role"] == "derived":
                require(f["mutability"] == "derived", where + ": derived role requires derived mutability")
            require(set(f["strategies"]) <= {"enum", "boundary", "bitflip", "arithmetic", "afl", "resize"}, where + ": unknown strategy")
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
            require(not runtime or (dep["op"] in RUNTIME_OPS and dep.get("multiply", 1) == 1),
                    f"{mid}: dependency not available in runtime: {dep['op']}")
            require(dep["target"] in fields[mid], f"{mid}: missing dependency target {dep['target']}")
            require(dep["target"] not in derived_targets, f"{mid}: multiple dependency writers for {dep['target']}")
            derived_targets.add(dep["target"])
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
            integer(dep.get("unit", 1), 1, 65507, f"{mid}.dependency.unit")
            integer(dep.get("multiply", 1), 1, 65507, f"{mid}.dependency.multiply")
            integer(dep.get("add", 0), -65507, 65507, f"{mid}.dependency.add")
            # Message size and codec-managed tag lengths are structural leaves.
            if sf != "$message" and dep["op"] not in {"correlate_request_response", "sequence_number"}:
                graph.setdefault((mid, dep["target"]), []).append((sm, sf))
    visiting, visited = set(), set()
    def walk(node):
        require(node not in visiting, f"dependency cycle at {node}")
        if node in visited: return
        visiting.add(node)
        for other in graph.get(node, []): walk(other)
        visiting.remove(node); visited.add(node)
    for node in graph: walk(node)
    for tr in state["transitions"]:
        require(tr["from"] in states and tr["to"] in states, "transition references missing state")
        require(tr["message"] in messages, "transition references missing message")
        if tr.get("response"):
            require(tr["response"] in messages, "transition references missing response")
            require(messages[tr["response"]]["direction"] in {"response", "both"}, "transition response has request direction")
    reached = {state["initial"]}
    for _ in states:
        reached |= {tr["to"] for tr in state["transitions"] if tr["from"] in reached}
    require(reached == set(states), "unreachable semantic state")
    return protocol, state


def compile_spec(protocol, state, output):
    validate(protocol, state)
    output = Path(output); output.mkdir(parents=True, exist_ok=True)
    p, s = copy.deepcopy(protocol), copy.deepcopy(state)
    p["ir_version"] = s["ir_version"] = 1
    for filename, obj in (("protocol_ir.json", p), ("state_ir.json", s)):
        (output / filename).write_text(json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=True) + "\n")
    result = {"protocol": p["protocol_id"], "messages": len(p["messages"]),
              "fields": sum(len(m["fields"]) for m in p["messages"]),
              "semantic_states": len(s["states"]), "validated": True,
              "runtime": p["support"]["runtime"], "scope": p["scope"],
              "example_validation": "protocol envelope and length consistency; not live service conformance"}
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
