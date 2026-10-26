#!/usr/bin/env python3
"""Apply explicit, shape-preserving field edits to an existing local binary file.

No automatic operation selection, sequence generation, target execution or state
feedback is provided. All requested fields are checked by the layout decoder.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile

if __package__:
    from .offline_protocol_decoder import (
        MAX_BYTES, LayoutDecoder, check_document_tree, keys, load_layout, require, unique_object,
    )
else:
    from offline_protocol_decoder import (
        MAX_BYTES, LayoutDecoder, check_document_tree, keys, load_layout, require, unique_object,
    )

MAX_EDITS = 256
EDITABLE_KINDS = {"uint", "int", "bytes", "bit"}
SHAPE_FIELDS = ("kind", "start", "end", "bit_lsb", "bit_width", "byte_order",
                "encoding", "source_node_path", "selected_case")


class EditError(ValueError):
    def __init__(self, message, diagnostic=None):
        super().__init__(message)
        self.diagnostic = diagnostic


@dataclass(frozen=True)
class EditResult:
    data: bytes
    report: dict


def _index_fields(tree):
    result, pending = {}, [tree]
    while pending:
        node = pending.pop()
        path = node["path"]
        if path in result:
            raise EditError(f"decoder produced duplicate path: {path}")
        result[path] = node
        pending.extend(node["children"])
    return result


def _shape(index):
    return {path: tuple(node.get(name) for name in SHAPE_FIELDS) for path, node in index.items()}


def _encode_leaf(node, value):
    """Return physical-byte masks, replacement bits and the canonical new value."""
    kind, width = node["kind"], node["end"] - node["start"]
    if kind not in EDITABLE_KINDS:
        raise EditError(f"only scalar, bit and bytes leaves can be edited: {node['path']}")
    if kind == "bytes":
        if type(value) is not str:
            raise EditError(f"bytes/text edit requires a string: {node['path']}")
        encoding = node["encoding"]
        if encoding == "hex":
            if re.fullmatch(r"(?:[0-9a-fA-F]{2})*", value) is None:
                raise EditError(f"hex edit requires complete byte pairs without separators: {node['path']}")
            raw = bytes.fromhex(value)
            canonical = raw.hex()
        elif encoding in ("ascii", "utf8"):
            try:
                raw = value.encode("ascii" if encoding == "ascii" else "utf-8")
            except UnicodeEncodeError as error:
                raise EditError(f"value cannot be encoded as {encoding}: {node['path']}") from error
            canonical = value
        else:
            raise EditError(f"unsupported decoder encoding metadata: {node['path']}")
        if len(raw) != width:
            raise EditError(f"encoded byte length must remain {width}: {node['path']}")
        return b"\xff" * width, raw, canonical
    if type(value) is not int:
        raise EditError(f"integer edits require an integer, not a boolean: {node['path']}")
    byte_order = node["byte_order"]
    if not 1 <= width <= 8 or byte_order not in ("big", "little"):
        raise EditError(f"invalid decoder scalar metadata: {node['path']}")
    if kind == "bit":
        bit_width, lsb = node["bit_width"], node["bit_lsb"]
        if not 0 <= value < 1 << bit_width:
            raise EditError(f"value exceeds the declared bit width: {node['path']}")
        mask = ((1 << bit_width) - 1) << lsb
        return mask.to_bytes(width, byte_order), (value << lsb).to_bytes(width, byte_order), value
    try:
        raw = value.to_bytes(width, byte_order, signed=kind == "int")
    except OverflowError as error:
        raise EditError(f"value exceeds the encoded integer width: {node['path']}") from error
    return b"\xff" * width, raw, value


def apply_field_edits(decoder, data, plan):
    """Return a validated copy; neither input data nor the supplied decoder is changed.

    Plan paths come from the diagnostic tree, never from caller-supplied offsets.
    Described constraints, selected branches and the complete field layout must
    still hold after all edits have been applied as one transaction.
    """
    require(isinstance(decoder, LayoutDecoder), "a loaded layout decoder is required")
    require(type(data) is bytes and len(data) <= MAX_BYTES, "input must be bytes of at most 1 MiB")
    check_document_tree(plan)
    require(len(json.dumps(plan, ensure_ascii=True).encode()) <= MAX_BYTES, "expanded edit plan exceeds 1 MiB")
    keys(plan, {"format", "version", "layout_sha256", "input_sha256", "edits"}, set(), "edit plan")
    require(plan["format"] == "stateafl.offline-edits", "unsupported edit plan format")
    require(type(plan["version"]) is int and plan["version"] == 1, "unsupported edit plan version")
    # Revalidate a private snapshot, rather than trusting externally mutable metadata.
    loaded = LayoutDecoder(decoder.description)
    input_digest = hashlib.sha256(data).hexdigest()
    require(plan["layout_sha256"] == loaded.digest, "edit plan does not match this layout")
    require(plan["input_sha256"] == input_digest, "edit plan does not match this input")
    edits = plan["edits"]
    require(type(edits) is list and 1 <= len(edits) <= MAX_EDITS, "edit plan requires 1..256 explicit edits")
    baseline = loaded.decode(data)
    if baseline["status"] != "decoded":
        raise EditError("input must decode completely before editing", baseline)
    before = _index_fields(baseline["tree"])
    requested, writes, seen = [], [], set()
    touched = bytearray(len(data))
    for edit in edits:
        keys(edit, {"path", "value"}, set(), "edit")
        path = edit["path"]
        require(type(path) is str and 0 < len(path) <= 8192, "edit path must be nonempty text of at most 8192 characters")
        require(path not in seen, f"duplicate edit path: {path}")
        seen.add(path)
        if path not in before:
            raise EditError(f"path was not present in the decoded input: {path}")
        node = before[path]
        mask, replacement, canonical = _encode_leaf(node, edit["value"])
        start, end = node["start"], node["end"]
        if not 0 <= start <= end <= len(data):
            raise EditError(f"decoder returned an invalid field range: {path}")
        for index, byte_mask in enumerate(mask, start):
            if touched[index] & byte_mask:
                raise EditError(f"edit overlaps another edit at byte {index}: {path}")
            touched[index] |= byte_mask
        writes.append((start, mask, replacement))
        requested.append({"path": path, "kind": node["kind"], "source_node_path": node["source_node_path"],
                          "start": start, "end": end, "previous_value": node["value"],
                          "new_value": canonical, "changed": node["value"] != canonical})
    output = bytearray(data)
    for start, mask, replacement in writes:
        for relative, (byte_mask, bits) in enumerate(zip(mask, replacement)):
            at = start + relative
            output[at] = (output[at] & (255 ^ byte_mask)) | (bits & byte_mask)
    candidate = bytes(output)
    decoded = loaded.decode(candidate)
    if decoded["status"] != "decoded":
        raise EditError("edited data violates the layout; no output was accepted", decoded)
    after = _index_fields(decoded["tree"])
    if _shape(before) != _shape(after):
        raise EditError("edit changes a branch, field range or structure; only shape-preserving edits are supported")
    for edit in requested:
        if after[edit["path"]]["value"] != edit["new_value"]:
            raise EditError(f"requested value did not survive decoding: {edit['path']}")
    if any((old ^ new) & (255 ^ mask) for old, new, mask in zip(data, candidate, touched)):
        raise EditError("an unspecified bit was changed; output was rejected")
    changed_bytes = sum(old != new for old, new in zip(data, candidate))
    report = {"format": "stateafl.offline-edit-result", "version": 1,
              "status": "edited" if changed_bytes else "unchanged", "layout_sha256": loaded.digest,
              "input_sha256": input_digest, "output_sha256": hashlib.sha256(candidate).hexdigest(),
              "byte_length": len(candidate), "changed_bytes": changed_bytes, "edits": requested,
              "layout_validated": True, "shape_preserved": True, "unspecified_bits_preserved": True,
              "scope": "explicit local field edits; validation covers only constraints expressed by the layout"}
    return EditResult(candidate, report)


def load_edit_plan(path):
    with Path(path).open("rb") as source:
        raw = source.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, "edit plan exceeds 1 MiB")
    def constant(value):
        raise EditError(f"invalid JSON constant {value}")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object, parse_constant=constant)


def write_new_file(path, data):
    """Publish complete bytes atomically without overwriting an existing path."""
    destination = Path(path)
    temporary = None
    published, cleanup_warning = False, None
    try:
        with tempfile.NamedTemporaryFile(prefix=".offline-edit-", dir=destination.parent, delete=False) as output:
            temporary = Path(output.name)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        # link() fails if the destination exists, including an existing symlink.
        os.link(temporary, destination)
        published = True
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError as error:
                if not published:
                    raise
                cleanup_warning = {"status": "temporary_cleanup_failed", "path": str(temporary), "error": str(error)}
    return cleanup_warning


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--layout", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--edits", type=Path, required=True, help="explicit, digest-bound JSON edit plan")
    parser.add_argument("--output", type=Path, required=True, help="new local output file; existing files are never overwritten")
    args = parser.parse_args()
    output_published = False
    try:
        require(args.input.resolve() != args.output.resolve(), "input and output must be different paths")
        decoder = load_layout(args.layout)
        plan = load_edit_plan(args.edits)
        with args.input.open("rb") as source:
            data = source.read(MAX_BYTES + 1)
        result = apply_field_edits(decoder, data, plan)
        cleanup_warning = write_new_file(args.output, result.data)
        output_published = True
        report = dict(result.report, output_path=str(args.output))
        if cleanup_warning is not None:
            report["warning"] = cleanup_warning
        print(json.dumps(report, ensure_ascii=True, indent=2), flush=True)
        return 0
    except (OSError, ValueError, TypeError, RecursionError, ImportError) as error:
        if isinstance(error, BrokenPipeError):
            # Avoid a second buffered stdout flush masking the publication status at exit.
            try:
                with open(os.devnull, "w") as sink:
                    os.dup2(sink.fileno(), sys.stdout.fileno())
            except (OSError, ValueError, AttributeError):
                pass
        report = {"status": "output_published_report_failed" if output_published else "edit_rejected", "error": str(error)}
        if output_published:
            report["output_path"] = str(args.output)
        if isinstance(error, EditError) and error.diagnostic is not None:
            report["decode_diagnostic"] = error.diagnostic
        print(json.dumps(report, ensure_ascii=True), file=sys.stderr)
        return 3 if output_published else 2


if __name__ == "__main__":
    raise SystemExit(main())
