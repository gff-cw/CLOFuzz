#!/usr/bin/env python3
"""Decode existing binary files using a protocol-independent layout tree.

No encoder, mutation API, transport or native codec dependency is provided.
The format is separate from ICP-IR; see docs/generic-offline-decoder.md.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path
import re
import sys

MAX_BYTES = 1 << 20
MAX_DEPTH = 32
MAX_LAYOUT_NODES = 4096
MAX_OUTPUT_NODES = 65536
MAX_REPEAT = 4096
MIN_INTEGER, MAX_INTEGER = -(1 << 63), (1 << 64) - 1
IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,62}\Z")
KINDS = {"struct", "uint", "int", "bytes", "bits", "choice", "repeat", "bounded", "align"}
OPERATIONS = {"add", "sub", "mul", "div", "mod", "and", "or", "xor", "shl", "shr"}


class LayoutError(ValueError):
    """Invalid description or unsupported capability."""


class DecodeError(ValueError):
    def __init__(self, status, message, path, offset):
        super().__init__(message)
        self.status, self.path, self.offset = status, path, offset


def require(condition, message):
    if not condition:
        raise LayoutError(message)


def integer(value, low, high, where):
    require(type(value) is int and low <= value <= high, f"{where}: expected integer in [{low}, {high}]")
    return value


def keys(value, required, optional, where):
    require(type(value) is dict, f"{where}: expected object")
    require(required <= value.keys(), f"{where}: missing {sorted(required - value.keys())}")
    require(value.keys() <= required | optional, f"{where}: unsupported keys {sorted(value.keys() - required - optional)}")


def identifier(value, where):
    require(isinstance(value, str) and IDENTIFIER.fullmatch(value), f"{where}: invalid identifier")


def check_document_tree(document):
    budget = [0]
    def walk(value, depth=0):
        budget[0] += 1
        require(depth <= MAX_DEPTH * 3 and budget[0] <= 65536, "description expansion budget exceeded")
        if type(value) is dict:
            require(all(type(key) is str for key in value), "mapping keys must be strings")
            for child in value.values():
                walk(child, depth + 1)
        elif type(value) is list:
            for child in value:
                walk(child, depth + 1)
        else:
            require(value is None or type(value) in (str, int, bool), "unsupported description scalar")
    walk(document)


def check_expression(value, depth=0):
    require(depth <= MAX_DEPTH, "expression depth exceeded")
    if type(value) is int:
        integer(value, MIN_INTEGER, MAX_INTEGER, "expression")
        return
    require(type(value) is dict, "expression must be an integer or expression object")
    if set(value) == {"ref"}:
        require(isinstance(value["ref"], str), "reference must be a string")
        parts = value["ref"].split(".")
        require(1 <= len(parts) <= MAX_DEPTH, "reference depth exceeded")
        for part in parts:
            identifier(part, "reference")
        return
    keys(value, {"op", "args"}, set(), "expression")
    require(isinstance(value["op"], str) and value["op"] in OPERATIONS, "unsupported expression operation")
    require(type(value["args"]) is list and len(value["args"]) == 2, "binary expression requires two operands")
    for argument in value["args"]:
        check_expression(argument, depth + 1)


def check_node(node, budget, depth=0):
    require(depth <= MAX_DEPTH, "layout depth exceeded")
    budget[0] += 1
    require(budget[0] <= MAX_LAYOUT_NODES, "layout node budget exceeded")
    require(type(node) is dict, "layout node must be an object")
    identifier(node.get("id"), "node.id")
    kind = node.get("kind")
    require(isinstance(kind, str) and kind in KINDS, f"unsupported layout kind {kind!r}")
    required, optional = set(), set()
    scalar = {"min", "max", "expected", "values"}
    if kind in {"uint", "int", "bits"}:
        required = {"width", "byte_order"}
        optional = scalar if kind != "bits" else {"fields"}
        integer(node.get("width"), 1, 8, "scalar.width")
        require(node.get("byte_order") in ("big", "little"), "byte_order must be big or little")
    elif kind == "bytes":
        required, optional = {"length"}, {"encoding", "expected_hex"}
        check_expression(node.get("length"))
        require(node.get("encoding", "hex") in ("hex", "ascii", "utf8"), "unsupported bytes encoding")
        if "expected_hex" in node:
            expected = node["expected_hex"]
            require(isinstance(expected, str) and len(expected) <= MAX_BYTES * 2 and
                    re.fullmatch(r"(?:[0-9a-fA-F]{2})*", expected) is not None, "invalid expected_hex")
    elif kind == "struct":
        required = {"fields"}
    elif kind == "choice":
        required, optional = {"selector", "cases"}, {"default"}
        check_expression(node.get("selector"))
        cases = node.get("cases")
        require(type(cases) is dict and 0 < len(cases) <= 256, "choice requires 1..256 cases")
        for selector, child in cases.items():
            require(isinstance(selector, str) and re.fullmatch(r"0|-?[1-9][0-9]{0,19}", selector), "case keys must be canonical decimal integers")
            integer(int(selector), MIN_INTEGER, MAX_INTEGER, "choice key")
            check_node(child, budget, depth + 1)
        if "default" in node:
            check_node(node["default"], budget, depth + 1)
    elif kind == "repeat":
        required = {"count", "max_items", "item"}
        check_expression(node.get("count"))
        integer(node.get("max_items"), 0, MAX_REPEAT, "repeat.max_items")
        check_node(node.get("item"), budget, depth + 1)
    elif kind == "bounded":
        required = {"length", "body"}
        check_expression(node.get("length"))
        check_node(node.get("body"), budget, depth + 1)
    elif kind == "align":
        required, optional = {"multiple"}, {"fill"}
        integer(node.get("multiple"), 1, 256, "align.multiple")
        if "fill" in node:
            integer(node["fill"], 0, 255, "align.fill")
    keys(node, {"id", "kind"} | required, optional, f"node {node['id']}")
    if kind in {"uint", "int"}:
        width = node["width"] * 8
        low = 0 if kind == "uint" else -(1 << (width - 1))
        high = (1 << width) - 1 if kind == "uint" else (1 << (width - 1)) - 1
        for name in scalar - {"values"}:
            if name in node:
                integer(node[name], low, high, f"scalar.{name}")
        require(node.get("min", low) <= node.get("max", high), "min exceeds max")
        minimum, maximum = node.get("min", low), node.get("max", high)
        if "expected" in node:
            require(minimum <= node["expected"] <= maximum, "expected value outside declared range")
        if "values" in node:
            require(type(node["values"]) is list and 0 < len(node["values"]) <= 256, "values requires 1..256 integers")
            for value in node["values"]:
                integer(value, low, high, "scalar.values")
                require(minimum <= value <= maximum, "enumeration value outside declared range")
            require(len(set(node["values"])) == len(node["values"]), "duplicate enumeration value")
            require("expected" not in node or node["expected"] in node["values"], "expected value absent from enumeration")
    if kind in {"struct", "bits"}:
        fields = node.get("fields")
        require(type(fields) is list and 0 < len(fields) <= 256, "fields requires 1..256 entries")
        seen, occupied = set(), 0
        for child in fields:
            require(type(child) is dict, "field must be an object")
            identifier(child.get("id"), "field.id")
            require(child["id"] not in seen, "duplicate sibling field id")
            seen.add(child["id"])
            if kind == "struct":
                check_node(child, budget, depth + 1)
            else:
                keys(child, {"id", "lsb", "width"}, {"expected"}, "bit field")
                integer(child["lsb"], 0, node["width"] * 8 - 1, "bits.lsb")
                integer(child["width"], 1, node["width"] * 8 - child["lsb"], "bits.width")
                mask = ((1 << child["width"]) - 1) << child["lsb"]
                require(not occupied & mask, "overlapping bit fields")
                occupied |= mask
                if "expected" in child:
                    integer(child["expected"], 0, (1 << child["width"]) - 1, "bits.expected")


@dataclass
class DecodedField:
    path: str
    kind: str
    start: int
    end: int
    value: object = None
    children: list["DecodedField"] = field(default_factory=list)
    bit_lsb: int | None = None
    bit_width: int | None = None
    byte_order: str | None = None
    encoding: str | None = None
    source_node_path: str = ""
    selected_case: str | None = None


class LayoutDecoder:
    def __init__(self, description):
        check_document_tree(description)
        keys(description, {"format", "version", "root"}, {"description"}, "layout")
        require(description["format"] == "stateafl.offline-layout", "unsupported layout format")
        require(type(description["version"]) is int and description["version"] == 1, "unsupported layout version")
        if "description" in description:
            require(isinstance(description["description"], str), "description must be text")
        check_node(description["root"], [0])
        serialized = json.dumps(description, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        require(len(serialized.encode()) <= MAX_BYTES, "layout exceeds description budget")
        self._description = json.loads(serialized)
        self.digest = hashlib.sha256(serialized.encode()).hexdigest()

    @property
    def description(self):
        """Return a copy so external edits cannot invalidate the loaded digest."""
        return json.loads(json.dumps(self._description))

    def decode(self, data):
        require(isinstance(data, bytes), "decode expects immutable bytes")
        require(len(data) <= MAX_BYTES, "input exceeds 1 MiB")
        return _Reader(self._description["root"], self.digest, data).decode()


class _Reader:
    def __init__(self, root, digest, data):
        self.root, self.digest, self.data = root, digest, data
        self.offset, self.nodes, self.expression_steps = 0, 0, 0
        self.bounded_depth = 0

    def error(self, status, message, path):
        raise DecodeError(status, message, path, self.offset)

    def expression(self, expression, scopes, path):
        self.expression_steps += 1
        if self.expression_steps > MAX_OUTPUT_NODES * 8:
            self.error("resource_limit", "expression evaluation budget exceeded", path)
        if type(expression) is int:
            return expression
        if "ref" in expression:
            parts = expression["ref"].split(".")
            for scope in reversed(scopes):
                if parts[0] in scope:
                    value = scope[parts[0]]
                    for part in parts[1:]:
                        if type(value) is not dict or part not in value:
                            self.error("invalid", "reference does not name a decoded integer", path)
                        value = value[part]
                    if type(value) is not int:
                        self.error("invalid", "reference does not name a decoded integer", path)
                    return value
            self.error("invalid", f"unresolved or forward reference {expression['ref']}", path)
        left, right = (self.expression(argument, scopes, path) for argument in expression["args"])
        op = expression["op"]
        if op in {"div", "mod"} and right == 0:
            self.error("invalid", "division by zero", path)
        if op == "div" and left % right:
            self.error("invalid", "non-integral division", path)
        if op in {"shl", "shr"} and not 0 <= right <= 63:
            self.error("invalid", "shift outside 0..63", path)
        if op in {"and", "or", "xor", "shl", "shr"} and (left < 0 or right < 0):
            self.error("invalid", "bit operation requires nonnegative operands", path)
        if op == "add": result = left + right
        elif op == "sub": result = left - right
        elif op == "mul": result = left * right
        elif op == "div": result = left // right
        elif op == "mod": result = left % right
        elif op == "and": result = left & right
        elif op == "or": result = left | right
        elif op == "xor": result = left ^ right
        elif op == "shl": result = left << right
        else: result = left >> right
        if not MIN_INTEGER <= result <= MAX_INTEGER:
            self.error("invalid", "expression integer overflow", path)
        return result

    def take(self, length, end, path):
        if type(length) is not int or not 0 <= length <= MAX_BYTES:
            self.error("invalid", "length outside supported bounds", path)
        if length > end - self.offset:
            self.error("invalid" if self.bounded_depth else "truncated", "field exceeds enclosing byte boundary", path)
        start = self.offset
        self.offset += length
        return self.data[start:self.offset]

    def node(self, spec, scopes, end, base, path=None, source_path="/root"):
        self.nodes += 1
        path = path or spec["id"]
        if self.nodes > MAX_OUTPUT_NODES:
            self.error("resource_limit", "decoded field budget exceeded", path)
        start, kind = self.offset, spec["kind"]
        result = DecodedField(path, kind, start, start, byte_order=spec.get("byte_order"),
                              encoding=spec.get("encoding", "hex") if kind == "bytes" else None,
                              source_node_path=source_path)
        if kind in {"uint", "int", "bits"}:
            raw = self.take(spec["width"], end, path)
            value = int.from_bytes(raw, spec["byte_order"], signed=kind == "int")
            if kind == "bits":
                value = {}
                container = int.from_bytes(raw, spec["byte_order"])
                for index, bit in enumerate(spec["fields"]):
                    self.nodes += 1
                    if self.nodes > MAX_OUTPUT_NODES:
                        self.error("resource_limit", "decoded field budget exceeded", path)
                    part = (container >> bit["lsb"]) & ((1 << bit["width"]) - 1)
                    if "expected" in bit and part != bit["expected"]:
                        self.error("invalid", "bit field differs from expected value", path + "." + bit["id"])
                    value[bit["id"]] = part
                    result.children.append(DecodedField(path + "." + bit["id"], "bit", start, self.offset,
                                                        part, bit_lsb=bit["lsb"], bit_width=bit["width"],
                                                        byte_order=spec["byte_order"],
                                                        source_node_path=f"{source_path}/fields/{index}"))
            else:
                if value < spec.get("min", MIN_INTEGER) or value > spec.get("max", MAX_INTEGER):
                    self.error("invalid", "scalar outside declared range", path)
                if "expected" in spec and value != spec["expected"]:
                    self.error("invalid", "scalar differs from expected value", path)
                if "values" in spec and value not in spec["values"]:
                    self.error("invalid", "scalar outside declared enumeration", path)
        elif kind == "bytes":
            raw = self.take(self.expression(spec["length"], scopes, path), end, path)
            if "expected_hex" in spec and raw != bytes.fromhex(spec["expected_hex"]):
                self.error("invalid", "bytes differ from expected value", path)
            encoding = spec.get("encoding", "hex")
            try:
                value = raw.hex() if encoding == "hex" else raw.decode("utf-8" if encoding == "utf8" else "ascii")
            except UnicodeDecodeError:
                self.error("invalid", "invalid text encoding", path)
        elif kind == "struct":
            value = {}
            for index, child in enumerate(spec["fields"]):
                decoded, child_value = self.node(child, scopes + [value], end, start, path + "." + child["id"],
                                                 f"{source_path}/fields/{index}")
                result.children.append(decoded)
                value[child["id"]] = child_value
        elif kind == "choice":
            selector = self.expression(spec["selector"], scopes, path)
            case = str(selector)
            matched = case in spec["cases"]
            child = spec["cases"][case] if matched else spec.get("default")
            if child is None:
                self.error("unsupported", f"no declared case for discriminator {selector}", path)
            result.selected_case = case if matched else f"default:{case}"
            child_source = f"{source_path}/cases/{case}" if matched else f"{source_path}/default"
            decoded, value = self.node(child, scopes, end, base, path + "." + child["id"], child_source)
            result.children.append(decoded)
        elif kind == "repeat":
            count = self.expression(spec["count"], scopes, path)
            if not 0 <= count <= spec["max_items"]:
                self.error("invalid", "repeat count outside declared bound", path)
            value = []
            for index in range(count):
                decoded, item = self.node(spec["item"], scopes, end, base, f"{path}[{index}]", f"{source_path}/item")
                result.children.append(decoded)
                value.append(item)
        elif kind == "bounded":
            length = self.expression(spec["length"], scopes, path)
            if not 0 <= length <= MAX_BYTES:
                self.error("invalid", "bounded length outside supported range", path)
            boundary = start + length
            if boundary > end:
                self.error("invalid" if self.bounded_depth else "truncated", "bounded region exceeds enclosing bytes", path)
            self.bounded_depth += 1
            try:
                decoded, value = self.node(spec["body"], scopes, boundary, start, path + "." + spec["body"]["id"],
                                           f"{source_path}/body")
            finally:
                self.bounded_depth -= 1
            result.children.append(decoded)
            if self.offset != boundary:
                self.error("invalid", "bounded body did not consume its declared length", path)
        else:
            padding = (-(self.offset - base)) % spec["multiple"]
            raw = self.take(padding, end, path)
            if "fill" in spec and any(byte != spec["fill"] for byte in raw):
                self.error("invalid", "alignment bytes differ from declared fill", path)
            value = raw.hex()
        result.end = self.offset
        if kind not in {"struct", "choice", "repeat", "bounded", "bits"}:
            result.value = value
        return result, value

    def decode(self):
        report = {"format": "stateafl.offline-decode", "version": 1,
                  "layout_sha256": self.digest, "input_sha256": hashlib.sha256(self.data).hexdigest(),
                  "input_length": len(self.data), "scope": "offline structural decoding only"}
        try:
            tree, _ = self.node(self.root, [], len(self.data), 0)
            if self.offset != len(self.data):
                self.error("invalid", "unconsumed trailing bytes", self.root["id"])
            report.update(status="decoded", tree=asdict(tree))
        except DecodeError as error:
            report.update(status=error.status, error=str(error), path=error.path, offset=error.offset)
        report["consumed"] = self.offset
        return report


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, f"duplicate mapping key {name!r}")
        result[name] = value
    return result


def load_layout(path):
    path = Path(path)
    with path.open("rb") as source:
        raw = source.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, "layout exceeds 1 MiB")
    if path.suffix.lower() in {".yaml", ".yml"}:
        import yaml

        class UniqueLoader(yaml.SafeLoader):
            pass

        def mapping(loader, node, deep=False):
            pairs = [(loader.construct_object(key, deep=deep), loader.construct_object(value, deep=deep))
                     for key, value in node.value]
            require(all(isinstance(name, str) for name, _ in pairs), "mapping keys must be strings")
            return unique_object(pairs)

        UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
        try:
            document = yaml.load(raw.decode("utf-8"), Loader=UniqueLoader)
        except yaml.YAMLError as error:
            raise LayoutError(f"invalid YAML: {error}") from error
    else:
        def constant(value):
            raise LayoutError(f"invalid JSON constant {value}")
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object, parse_constant=constant)
    return LayoutDecoder(document)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--layout", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True, help="existing binary file")
    args = parser.parse_args()
    try:
        decoder = load_layout(args.layout)
        with args.input.open("rb") as source:
            data = source.read(MAX_BYTES + 1)
        report = decoder.decode(data)
        print(json.dumps(report, ensure_ascii=True, indent=2))
        return 0 if report["status"] == "decoded" else 1
    except (LayoutError, OSError, ValueError, TypeError, RecursionError, ImportError) as error:
        print(json.dumps({"status": "description_or_input_error", "error": str(error)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
