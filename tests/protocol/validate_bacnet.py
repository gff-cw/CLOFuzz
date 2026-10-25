#!/usr/bin/env python3
"""Exercise the locally built BACnet server over loopback UDP, without fuzzing.

The existing replay corpus is read only. Its LE32 record headers are transport
metadata, so only each BACnet/IP record is sent on the wire. Device-123 requests
are also tested as-is before a copy is addressed to the configured test device.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time


def replay_records(data):
    if data[:1] == b"\x81":
        return [data], "raw-datagram"
    records = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            raise ValueError("truncated LE32 replay length")
        size = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        if not size or size > len(data) - offset:
            raise ValueError("invalid LE32 replay record size")
        records.append(data[offset:offset + size])
        offset += size
    if not records:
        raise ValueError("empty replay")
    return records, "LE32-length-prefixed"


def tags(data):
    decoded = []
    offset = 0
    while offset < len(data):
        first = data[offset]
        offset += 1
        number, context, size = first >> 4, bool(first & 8), first & 7
        if number == 15:
            number = data[offset]
            offset += 1
        item = {"tag": number, "context": context}
        if context and size in (6, 7):
            item["kind"] = "opening" if size == 6 else "closing"
            decoded.append(item)
            continue
        if size == 5:
            size = data[offset]
            offset += 1
            if size == 254:
                size = int.from_bytes(data[offset:offset + 2], "big")
                offset += 2
            elif size == 255:
                size = int.from_bytes(data[offset:offset + 4], "big")
                offset += 4
        if not context and number == 1:
            item["value"] = bool(size)
            size = 0
        if offset + size > len(data):
            raise ValueError("truncated BACnet tag")
        value = data[offset:offset + size]
        offset += size
        item["bytes"] = value.hex()
        if context or number in (2, 3, 9):
            item["value"] = int.from_bytes(value, "big", signed=not context and number == 3)
        elif number == 7 and value:
            item["encoding"] = value[0]
            item["value"] = value[1:].decode("utf-8", errors="replace")
        elif number == 12 and len(value) == 4:
            identifier = int.from_bytes(value, "big")
            item["value"] = {"type": identifier >> 22, "instance": identifier & 0x3fffff}
        decoded.append(item)
    return decoded


def decode_packet(packet):
    if len(packet) < 8 or packet[0] != 0x81:
        raise ValueError("not a complete BACnet/IPv4 packet")
    length = int.from_bytes(packet[2:4], "big")
    if length != len(packet):
        raise ValueError(f"BVLC length {length} differs from datagram {len(packet)}")
    offset = 10 if packet[1] == 4 else 4  # Forwarded-NPDU has an originating address.
    if packet[offset] != 1:
        raise ValueError("unexpected NPDU version")
    control = packet[offset + 1]
    offset += 2
    if control & 0x20:
        address_length = packet[offset + 2]
        offset += 3 + address_length
    if control & 0x08:
        address_length = packet[offset + 2]
        offset += 3 + address_length
    if control & 0x20:
        offset += 1
    if control & 0x80:
        raise ValueError("network-layer message is outside this check")
    apdu = packet[offset:]
    kind = apdu[0] >> 4
    result = {"bvlc_function": packet[1], "bvlc_length": length,
              "npdu_control": control, "apdu_type": kind}
    if kind == 1:
        result.update(service=apdu[1], tags=tags(apdu[2:]))
    elif kind == 0:
        if apdu[0] & 8:
            raise ValueError("segmented request is outside this check")
        result.update(invoke_id=apdu[2], service=apdu[3], tags=tags(apdu[4:]))
    elif kind in (3, 5):
        if kind == 3 and apdu[0] & 8:
            raise ValueError("segmented acknowledgment is outside this check")
        result.update(invoke_id=apdu[1], service=apdu[2], tags=tags(apdu[3:]))
    else:
        result["apdu_hex"] = apdu.hex()
    return result


def verify_iam(parsed, device):
    assert parsed["apdu_type"] == 1 and parsed["service"] == 0, parsed
    values = parsed["tags"]
    assert values[0]["tag"] == 12 and values[0]["value"] == {"type": 8, "instance": device}, parsed
    assert values[1]["tag"] == 2 and values[1]["value"] > 0, parsed
    assert values[2]["tag"] == 9 and values[3]["tag"] == 2, parsed


def verify_read(parsed, request, device):
    assert parsed["apdu_type"] == 3 and parsed["service"] == 12, parsed
    assert parsed["invoke_id"] == request["invoke_id"], parsed
    req_tags, ack_tags = request["tags"], parsed["tags"]
    assert ack_tags[0]["tag"] == 0 and ack_tags[0]["value"] == (8 << 22 | device), parsed
    assert ack_tags[1]["tag"] == 1 and ack_tags[1]["value"] == req_tags[1]["value"], parsed
    values = [item for item in ack_tags if not item["context"]]
    prop = req_tags[1]["value"]
    if prop in (77, 121):
        assert len(values) == 1 and values[0]["tag"] == 7 and values[0]["value"], parsed
    elif prop == 76:
        assert ack_tags[2]["tag"] == 2 and ack_tags[2]["value"] == 0, parsed
        assert len(values) == 1 and values[0]["tag"] == 2 and values[0]["value"] > 0, parsed
    else:
        raise ValueError(f"unexpected corpus property {prop}")
    assert any(item.get("kind") == "opening" and item["tag"] == 3 for item in ack_tags), parsed
    assert ack_tags[-1].get("kind") == "closing" and ack_tags[-1]["tag"] == 3, parsed


def main():
    workspace = Path(__file__).resolve().parents[3]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, default=workspace / "bacnet-stack/build-protocol-integration/server")
    parser.add_argument("--inputs", type=Path, default=workspace / "bacnet-stack/inputs")
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parent / "evidence/new-build")
    parser.add_argument("--port", type=int, default=47818)
    parser.add_argument("--device", type=int, default=1234)
    args = parser.parse_args()
    args.server = args.server.resolve()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    target = ("127.0.0.1", args.port)
    result = {"server": str(args.server), "device_instance": args.device,
              "interface": "lo", "target": list(target), "corpus": [], "checks": []}
    corpus = {}
    for source in sorted(args.inputs.glob("*.replay")):
        data = source.read_bytes()
        records, framing = replay_records(data)
        entry = {"file": str(source.resolve()), "sha256": hashlib.sha256(data).hexdigest(),
                 "framing": framing, "records": []}
        for record in records:
            item = {"bytes": len(record), "hex": record.hex()}
            try:
                item["decoded"] = decode_packet(record)
            except (ValueError, IndexError) as error:
                item["decode_error"] = str(error)
            entry["records"].append(item)
        result["corpus"].append(entry)
        corpus[source.name] = records
    # Fail before launching if another process already owns the requested port.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(target)
    env = os.environ.copy()
    env.update(BACNET_IFACE="lo", BACNET_IP_PORT=str(args.port), BACNET_IP_DEBUG="1")
    for key in list(env):
        if key.startswith("__AFL_"):
            del env[key]
    command = ["stdbuf", "-oL", "-eL", str(args.server), str(args.device)]
    result["server_command"] = command
    result["environment"] = {key: env[key] for key in ("BACNET_IFACE", "BACNET_IP_PORT", "BACNET_IP_DEBUG")}
    process = None
    error = None
    try:
        with tempfile.TemporaryDirectory(prefix="bacnet-normal-", dir=args.output_dir) as workdir, \
                (args.output_dir / "server.log").open("w") as log, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.bind(("127.0.0.1", 0))
            process = subprocess.Popen(command, env=env, cwd=workdir, stdout=log, stderr=subprocess.STDOUT)
            client.settimeout(0.15)
            whois = corpus["seed01_whois.replay"][0]
            deadline = time.monotonic() + 5
            while True:
                if process.poll() is not None:
                    raise RuntimeError(f"server exited with {process.returncode}; inspect server.log")
                client.sendto(whois, target)
                try:
                    packet, peer = client.recvfrom(65535)
                    assert peer == target, peer
                    verify_iam(decode_packet(packet), args.device)
                    break
                except socket.timeout:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("server did not answer startup Who-Is")
            result["client"] = list(client.getsockname())

            def exchange(name, request, expected):
                client.settimeout(1.0 if expected != "silence" else 0.3)
                item = {"name": name, "request_hex": request.hex(),
                        "request": decode_packet(request), "expected": expected}
                client.sendto(request, target)
                try:
                    packet, peer = client.recvfrom(65535)
                    assert peer == target, peer
                    item.update(response_hex=packet.hex(), response=decode_packet(packet), peer=list(peer))
                    assert expected != "silence", item
                except socket.timeout:
                    assert expected == "silence", f"timeout in {name}"
                    item["response"] = None
                result["checks"].append(item)
                return item

            item = exchange("original Who-Is", whois, "I-Am")
            verify_iam(item["response"], args.device)
            item["passed"] = True
            item = exchange("original range 0..100 excludes Device 1234", corpus["seed02_whois_range.replay"][0], "silence")
            item["passed"] = True
            # Keep the original seed immutable; encode Device 1234 limits in a copy.
            identifier = args.device.to_bytes(max(1, (args.device.bit_length() + 7) // 8), "big")
            ranged = bytearray(whois + bytes([0x08 | len(identifier)]) + identifier + bytes([0x18 | len(identifier)]) + identifier)
            ranged[2:4] = len(ranged).to_bytes(2, "big")
            item = exchange("Who-Is range adapted to test device", bytes(ranged), "I-Am")
            verify_iam(item["response"], args.device)
            item["passed"] = True
            for filename in ("seed03_read_objectname.replay", "seed04_read_vendorname.replay", "seed05_read_objectlist.replay"):
                original = corpus[filename][0]
                request = decode_packet(original)
                original_device = request["tags"][0]["value"] & 0x3fffff
                if original_device != args.device:
                    item = exchange(filename + " original device", original, "Error unknown-object")
                    parsed = item["response"]
                    assert parsed["apdu_type"] == 5 and parsed["service"] == 12, parsed
                    assert parsed["invoke_id"] == request["invoke_id"], parsed
                    assert [tag["value"] for tag in parsed["tags"]] == [1, 31], parsed
                    item["passed"] = True
                encoded = (8 << 22 | original_device).to_bytes(4, "big")
                adapted = original.replace(b"\x0c" + encoded, b"\x0c" + (8 << 22 | args.device).to_bytes(4, "big"), 1)
                item = exchange(filename + " adapted device", adapted, "Complex-ACK ReadProperty")
                verify_read(item["response"], item["request"], args.device)
                item["passed"] = True
            assert process.poll() is None, "server exited during normal communication"
            result["server_alive_after_checks"] = True
            result["passed"] = True
    except Exception as caught:
        error = caught
        result.update(passed=False, error=f"{type(caught).__name__}: {caught}")
    finally:
        if process is not None:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
            result["server_exit_after_cleanup"] = process.returncode
        for entry in result["corpus"]:
            assert hashlib.sha256(Path(entry["file"]).read_bytes()).hexdigest() == entry["sha256"], "corpus modified"
        (args.output_dir / "communication.json").write_text(json.dumps(result, indent=2) + "\n")
    if error is not None:
        print(result["error"], file=sys.stderr)
        return 1
    print(f"PASS: {len(result['checks'])} BACnet loopback checks; evidence: {args.output_dir / 'communication.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
