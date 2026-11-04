"""Schema-owned structure and provenance for legacy profile instantiation.

This module checks object shape without invoking a codec, target or compiler.
It intentionally does not interpret example values, conditions or expressions.
The legacy compiler remains responsible for type and executable semantics.
"""
import copy
import hashlib
import json
from pathlib import Path
import re

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TEMPLATES = ROOT / "protocols/templates"
DEFAULT_SCHEMAS = ROOT / "protocols/schema"
DOCUMENTS = ("protocol_spec", "state_transition")
EXPLICIT_MESSAGE_KEYS = frozenset(("fixture_status", "runtime_encode"))
FIELD_CLASSIFICATIONS = frozenset(("executed", "annotation_with_validation", "static_only",
                                   "codec_managed_or_static", "head_suggestions_only",
                                   "head_or_variable_leaf_strategy"))


class TemplateContractError(ValueError):
    """A package and its common structural contract have drifted."""


class _UniqueTemplateLoader(yaml.SafeLoader):
    pass


def _unique_yaml_mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise TemplateContractError("template object keys must be strings")
        if key in result:
            raise TemplateContractError(f"duplicate template key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueTemplateLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_yaml_mapping)


def _read_yaml(path):
    try:
        return yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueTemplateLoader)
    except yaml.YAMLError as error:
        raise TemplateContractError(f"{path}: invalid template contract YAML: {error}") from error


def _unique_json_mapping(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise TemplateContractError(f"duplicate contract JSON key: {key}")
        result[key] = value
    return result


def _read_json(path):
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_json_mapping)


def _same_json(left, right):
    # Python equality conflates True with 1; source identity must retain types.
    return json.dumps(left, sort_keys=True, ensure_ascii=False) == json.dumps(right, sort_keys=True, ensure_ascii=False)


def _check_fragment_source(item, profiles):
    """Bind real excerpts to repository sources, not a caller's template path."""
    where = "fragment " + item["id"]
    source = item.get("source")
    if not isinstance(source, dict):
        raise TemplateContractError(f"{where}: missing explicit source scope")
    if source.get("kind") == "rule_syntax_only":
        if source.get("industrial_profile_claim") is not False:
            raise TemplateContractError(f"{where}: syntax-only source must disclaim an industrial profile")
        return
    if source.get("kind") != "profile_excerpt":
        raise TemplateContractError(f"{where}: unknown fragment source kind")
    profile = source.get("profile")
    if not isinstance(profile, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,62}", profile):
        raise TemplateContractError(f"{where}: invalid source profile")
    relative = f"protocols/{profile}/protocol_spec.yaml"
    if source.get("source_file") != relative:
        raise TemplateContractError(f"{where}: source file must match its profile")
    path = ROOT / relative
    try:
        path.resolve().relative_to(ROOT.resolve())
    except ValueError as error:
        raise TemplateContractError(f"{where}: source file escapes the repository") from error
    if profile not in profiles:
        with path.open("rb") as stream:
            data = stream.read(2**20 + 1)
        if len(data) > 2**20:
            raise TemplateContractError(f"{where}: source profile exceeds 1 MiB")
        profiles[profile] = (hashlib.sha256(data).hexdigest(), _read_yaml(path))
    digest, document = profiles[profile]
    if source.get("source_sha256") != digest:
        raise TemplateContractError(f"{where}: stale source profile SHA256")
    if not isinstance(source.get("message"), str):
        raise TemplateContractError(f"{where}: missing source message identity")
    messages = {message["id"]: message for message in document["messages"]}
    message = messages.get(source["message"])
    if message is None:
        raise TemplateContractError(f"{where}: source message does not exist")
    pointer = item["schema_pointer"]
    if pointer == "#/properties/messages/items/properties/dependencies/items":
        matches = any(_same_json(item["selection"], value) for value in message["dependencies"])
    elif pointer in {"#/properties/messages/items/properties/fields/items", "#/$defs/structure"}:
        field = next((field for field in message["fields"] if field["id"] == source.get("field")), None)
        expected = field.get("structure_model") if field is not None and pointer == "#/$defs/structure" else field
        matches = expected is not None and _same_json(item["selection"], expected)
    else:
        raise TemplateContractError(f"{where}: source excerpt component requires an explicit contract")
    if not matches:
        raise TemplateContractError(f"{where}: selection differs from its declared source excerpt")
    context = item.get("context", {})
    if not isinstance(context, dict) or not isinstance(context.get("fields", {}), dict):
        raise TemplateContractError(f"{where}: invalid source field context")
    if "message_direction" in context and context["message_direction"] != message["direction"]:
        raise TemplateContractError(f"{where}: source message direction differs from context")
    for mid, fields in context.get("fields", {}).items():
        actual = messages.get(mid, {}).get("fields", [])
        if not isinstance(fields, list) or not all(any(_same_json(field, value) for value in actual) for field in fields):
            raise TemplateContractError(f"{where}: context fields differ from their source message")
    if "count_field" in context and not any(_same_json(context["count_field"], field) for field in message["fields"]):
        raise TemplateContractError(f"{where}: context count field differs from its source message")


def _resolve(schema, root):
    if not isinstance(schema, dict):
        raise TemplateContractError("schema component must be an object")
    if "$ref" not in schema:
        return schema
    reference = schema["$ref"]
    if not isinstance(reference, str) or not reference.startswith("#/"):
        raise TemplateContractError("template contracts require local schema references")
    result = root
    try:
        for part in reference[2:].split("/"):
            result = result[part.replace("~1", "/").replace("~0", "~")]
    except (KeyError, TypeError) as error:
        raise TemplateContractError(f"missing schema reference: {reference}") from error
    return result


def check_object_shape(document, schema, *, where="document", root=None, depth=0):
    """Check recursive required/known keys, including nested local $ref nodes.

    This is deliberately a shape check: a skeleton can contain placeholders.
    JSON Schema types, ranges, enums and cross-field semantics are checked by
    proto_spec_compiler.validate after a concrete profile has been copied.
    """
    if depth > 96:
        raise TemplateContractError(f"{where}: structural nesting exceeds 96")
    root = schema if root is None else root
    resolved = _resolve(schema, root)
    if resolved is not schema:
        return check_object_shape(document, resolved, where=where, root=root, depth=depth + 1)
    if any(key in schema for key in ("allOf", "anyOf", "oneOf", "if", "then", "else")):
        raise TemplateContractError(f"{where}: schema combination needs an explicit template contract update")
    if schema.get("type") == "object":
        if not isinstance(document, dict):
            raise TemplateContractError(f"{where}: expected object structure")
        if not all(isinstance(key, str) for key in document):
            raise TemplateContractError(f"{where}: object keys must be strings")
        properties = schema.get("properties", {})
        missing = set(schema.get("required", ())) - set(document)
        unknown = set(document) - set(properties)
        if missing:
            raise TemplateContractError(f"{where}: missing required keys: {', '.join(sorted(missing))}")
        if unknown and schema.get("additionalProperties") is False:
            raise TemplateContractError(f"{where}: unknown keys: {', '.join(sorted(unknown))}")
        for key, value in document.items():
            if key in properties:
                check_object_shape(value, properties[key], where=f"{where}.{key}", root=root, depth=depth + 1)
    elif schema.get("type") == "array":
        if not isinstance(document, list):
            raise TemplateContractError(f"{where}: expected array structure")
        if len(document) < schema.get("minItems", 0) or len(document) > schema.get("maxItems", 65536):
            raise TemplateContractError(f"{where}: array size outside structural schema bounds")
        for index, value in enumerate(document):
            check_object_shape(value, schema.get("items", {}), where=f"{where}[{index}]", root=root, depth=depth + 1)


def _read_contract_files(template_directory=None, schema_directory=None):
    templates = Path(template_directory or DEFAULT_TEMPLATES)
    schemas = Path(schema_directory or DEFAULT_SCHEMAS)
    result = []
    for name in DOCUMENTS:
        template_path = templates / (name + ".template.yaml")
        schema_path = schemas / (name + ".schema.json")
        skeleton = _read_yaml(template_path)
        schema = _read_json(schema_path)
        if not isinstance(skeleton, dict) or not isinstance(schema, dict):
            raise TemplateContractError(f"{name}: template and schema must be objects")
        check_object_shape(skeleton, schema, where=name + ".template")
        result.append((name, skeleton, schema, template_path, schema_path))
    return result


def checked_profile_copy(protocol, state, *, template_directory=None, schema_directory=None):
    """Copy concrete values, preserving every schema-known property.

    Schemas own shape; templates demonstrate required shape; profiles own wire
    values and defaults. No template example value silently rewrites a real
    protocol. A schema extension cannot be discarded by top-level projection.
    """
    files = _read_contract_files(template_directory, schema_directory)
    load_capability_catalog(template_directory=template_directory, schema_directory=schema_directory)
    documents = []
    for source, (name, skeleton, schema, _, _) in zip(
            (protocol, state), files):
        check_object_shape(source, schema, where=name + ".profile")
        if not isinstance(source, dict):
            raise TemplateContractError(f"{name}: concrete profile must be an object")
        # Preserve a readable common top-level order, then every permitted
        # optional extension. Neither branch takes values from the skeleton.
        ordered = {key: copy.deepcopy(source[key]) for key in skeleton if key in source}
        ordered.update({key: copy.deepcopy(value) for key, value in source.items() if key not in ordered})
        documents.append(ordered)
    for index, message in enumerate(documents[0].get("messages", ())):
        if not isinstance(message, dict):
            raise TemplateContractError(f"message[{index}]: concrete message must be an object")
        missing = EXPLICIT_MESSAGE_KEYS - set(message)
        if missing:
            raise TemplateContractError(f"message[{index}]: generated packages require explicit {', '.join(sorted(missing))}")
    return tuple(documents)


def load_capability_catalog(*, template_directory=None, schema_directory=None):
    """Check catalog coverage against the schema, without loading a codec."""
    directory = Path(template_directory or DEFAULT_TEMPLATES) / "legacy_contract"
    catalog = _read_json(directory / "capabilities.json")
    if not isinstance(catalog, dict) or catalog.get("format") != "stateafl.legacy-template-capabilities" or type(catalog.get("version")) is not int or catalog["version"] != 1:
        raise TemplateContractError("unsupported legacy template capability contract")
    schemas = {name: schema for name, _, schema, _, _ in
               _read_contract_files(template_directory, schema_directory)}
    messages = schemas["protocol_spec"]["properties"]["messages"]["items"]["properties"]
    if not _same_json(catalog.get("supported_codecs"), schemas["protocol_spec"]["properties"]["codec"]["enum"]):
        raise TemplateContractError("capability catalog codecs differ from schema")
    if (not isinstance(catalog.get("direction"), dict)
            or not _same_json(catalog["direction"].get("static"), messages["direction"]["enum"])
            or not _same_json(catalog["direction"].get("online"), ["request", "response"])):
        raise TemplateContractError("capability catalog direction contract differs from schema/runtime")
    explicit = catalog.get("explicit_packaging_message_keys")
    if (not isinstance(explicit, list) or not all(isinstance(key, str) for key in explicit)
            or len(explicit) != len(EXPLICIT_MESSAGE_KEYS) or set(explicit) != EXPLICIT_MESSAGE_KEYS):
        raise TemplateContractError("capability catalog explicit message keys differ from packaging contract")
    operation_names = messages["dependencies"]["items"]["properties"]["op"]["enum"]
    operations = catalog.get("dependency_operations", [])
    if not isinstance(operations, list) or not all(isinstance(entry, dict) and isinstance(entry.get("op"), str)
                                                 and entry.get("classification") in {"executed", "codec_managed", "static_only"}
                                                 for entry in operations):
        raise TemplateContractError("invalid capability dependency classifications")
    supplied = [entry.get("op") for entry in operations]
    if len(set(supplied)) != len(supplied) or set(supplied) != set(operation_names):
        raise TemplateContractError("capability catalog dependency operations differ from schema")
    field_properties = catalog.get("field_properties")
    if not isinstance(field_properties, dict) or set(field_properties) != FIELD_CLASSIFICATIONS or not all(isinstance(names, list) and all(isinstance(name, str) for name in names)
                                                        for names in field_properties.values()):
        raise TemplateContractError("invalid capability field classifications")
    properties = [name for names in field_properties.values() for name in names]
    if len(set(properties)) != len(properties) or set(properties) != set(messages["fields"]["items"]["properties"]):
        raise TemplateContractError("capability catalog field classifications differ from schema")
    fragments = _read_yaml(directory / "advanced_fragments.yaml")
    if not isinstance(fragments, dict) or fragments.get("format") != "stateafl.legacy-capability-fragments" or type(fragments.get("version")) is not int or fragments["version"] != 1:
        raise TemplateContractError("unsupported legacy capability fragments")
    if fragments.get("runtime_tests_executed") is not False:
        raise TemplateContractError("capability fragment source cannot claim runtime acceptance")
    examples = fragments.get("fragments")
    if not isinstance(examples, list) or not all(isinstance(item, dict) for item in examples):
        raise TemplateContractError("capability fragments must contain an array of objects")
    identifiers = [item.get("id") for item in examples]
    if not all(isinstance(name, str) and name for name in identifiers) or len(set(identifiers)) != len(identifiers):
        raise TemplateContractError("invalid or duplicate capability fragment id")
    additional = catalog.get("additional_fragments", [])
    if not isinstance(additional, list):
        raise TemplateContractError("additional capability fragments must be an array")
    referenced = [entry.get("fragment") for entry in operations] + additional
    if not all(isinstance(name, str) for name in referenced):
        raise TemplateContractError("invalid capability fragment reference")
    if set(referenced) != set(identifiers) or len(referenced) != len(identifiers):
        raise TemplateContractError("capability catalog fragment inventory differs from examples")
    by_id = {item["id"]: item for item in examples}
    for operation in operations:
        fragment = by_id[operation["fragment"]]
        if (fragment.get("classification") != operation["classification"]
                or not isinstance(fragment.get("selection"), dict)
                or fragment["selection"].get("op") != operation["op"]):
            raise TemplateContractError("capability dependency classification/operation differs from its fragment")
    profiles = {}
    validators = {name: jsonschema.Draft202012Validator(schema) for name, schema in schemas.items()}
    for item in examples:
        document = item.get("schema_document", "protocol_spec")
        if not isinstance(document, str) or document not in schemas or not isinstance(item.get("schema_pointer"), str) or "selection" not in item:
            raise TemplateContractError(f"fragment {item['id']}: invalid schema component reference")
        schema = schemas[document]
        component = _resolve({"$ref": item["schema_pointer"]}, schema)
        check_object_shape(item["selection"], component, where="fragment." + item["id"], root=schema)
        # Unlike placeholder skeletons, fragments contain concrete values.
        # descend retains the original schema's local-reference resolution.
        error = next(validators[document].descend(item["selection"], component), None)
        if error is not None:
            raise TemplateContractError(f"fragment {item['id']}: invalid schema component value: {error.message}")
        _check_fragment_source(item, profiles)
    return catalog


def contract_metadata(*, template_directory=None, schema_directory=None):
    """Record exact structural inputs; hashes do not certify runtime behavior."""
    files = _read_contract_files(template_directory, schema_directory)
    records = {}
    for name, _, _, template_path, schema_path in files:
        records[name] = {
            "template_sha256": hashlib.sha256(template_path.read_bytes()).hexdigest(),
            "schema_sha256": hashlib.sha256(schema_path.read_bytes()).hexdigest(),
        }
    catalog_path = Path(template_directory or DEFAULT_TEMPLATES) / "legacy_contract/capabilities.json"
    load_capability_catalog(template_directory=template_directory, schema_directory=schema_directory)
    return {
        "format": "stateafl.legacy-template-instantiation", "version": 1,
        "provenance_scope": "package creation only; later edited output requires current model and corpus validation",
        "structure_authority": "protocols/schema/*.schema.json",
        "concrete_value_authority": "selected source profile; every schema-known property is preserved",
        "skeleton_value_policy": "illustrative only; nested defaults and dependencies never override source profile values",
        "shape_check": "recursive required/known object keys, including local schema references",
        "concrete_semantic_check": "proto_spec_compiler.validate before package publication",
        "explicit_message_fields": sorted(EXPLICIT_MESSAGE_KEYS),
        "descriptions": records,
        "capability_catalog_sha256": hashlib.sha256(catalog_path.read_bytes()).hexdigest(),
        "capability_fragments_sha256": hashlib.sha256((catalog_path.parent / "advanced_fragments.yaml").read_bytes()).hexdigest(),
        "runtime_tests_executed_by_instantiator": False,
        "new_codec_generated": False,
    }
